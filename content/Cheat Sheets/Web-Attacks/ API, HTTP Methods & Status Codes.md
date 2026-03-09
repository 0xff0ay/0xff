---
title: API, HTTP Methods & Status Codes
description: Comprehensive reference covering APIs, HTTP protocol mechanics, request/response lifecycle, HTTP methods, headers, and all status codes with detailed explanations.
navigation:
  icon: i-lucide-globe
---

## Overview

Understanding **APIs**, **HTTP methods**, and **status codes** is foundational for web development, penetration testing, and system administration. This cheatsheet provides an in-depth reference covering how the web communicates, how APIs function, and what every HTTP status code means.

> HTTP (HyperText Transfer Protocol) is the backbone of data communication on the World Wide Web. Every web interaction — from loading a page to making an API call — relies on HTTP.

---

## What is an API?

An **API (Application Programming Interface)** is a set of rules and protocols that allows different software applications to communicate with each other. APIs define how requests should be made, what data formats are used, and how responses are returned.

### API Types

| Type              | Protocol       | Data Format    | Description                                          |
| ----------------- | -------------- | -------------- | ---------------------------------------------------- |
| REST              | HTTP/HTTPS     | JSON / XML     | Stateless, resource-based, most widely used          |
| SOAP              | HTTP / SMTP    | XML            | Strict standards, WS-Security, enterprise focused    |
| GraphQL           | HTTP/HTTPS     | JSON           | Query language, client specifies data shape           |
| gRPC              | HTTP/2         | Protobuf       | High-performance, binary serialization, streaming    |
| WebSocket         | WS / WSS       | JSON / Binary  | Full-duplex, real-time bidirectional communication   |
| JSON-RPC          | HTTP / TCP     | JSON           | Remote procedure call with JSON encoding             |
| XML-RPC           | HTTP           | XML            | Remote procedure call with XML encoding              |
| OData             | HTTP/HTTPS     | JSON / XML     | Standardized RESTful API protocol by Microsoft       |
| Webhook           | HTTP/HTTPS     | JSON           | Event-driven, server pushes data to client URL       |
| SSE               | HTTP/HTTPS     | Text stream    | Server-Sent Events, one-way real-time from server    |

### API Architecture Styles

| Style              | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| **Monolithic**     | Single unified API serving all functions                     |
| **Microservices**  | Multiple small APIs each handling specific business domain   |
| **Serverless**     | APIs running as cloud functions (AWS Lambda, Azure Functions)|
| **API Gateway**    | Central entry point routing to backend microservices         |
| **BFF (Backend for Frontend)** | Separate API layer tailored per client type       |
| **Event-Driven**   | APIs triggered by events through message queues              |

---

## REST API Deep Dive

REST (Representational State Transfer) is the most common API architecture style.

### REST Principles

| Principle              | Description                                                    |
| ---------------------- | -------------------------------------------------------------- |
| **Stateless**          | Each request contains all info needed; no session on server    |
| **Client-Server**      | Client and server are independent and loosely coupled          |
| **Cacheable**          | Responses can be cached to improve performance                 |
| **Uniform Interface**  | Standardized resource access via URIs and HTTP methods         |
| **Layered System**     | Client can't tell if connected directly or via intermediary    |
| **Code on Demand**     | Server can extend client functionality (optional)              |

### REST Resource Naming Conventions

::code-preview
---
class: "[&>div]:*:my-0"
---
RESTful URL design patterns.

#code
```
# Good REST URL patterns
GET    /api/v1/users              # Get all users
GET    /api/v1/users/123          # Get specific user
POST   /api/v1/users              # Create new user
PUT    /api/v1/users/123          # Update entire user
PATCH  /api/v1/users/123          # Partial update user
DELETE /api/v1/users/123          # Delete user

# Nested resources
GET    /api/v1/users/123/orders           # Get user's orders
GET    /api/v1/users/123/orders/456       # Get specific order
POST   /api/v1/users/123/orders           # Create order for user

# Filtering, sorting, pagination
GET    /api/v1/users?status=active
GET    /api/v1/users?sort=name&order=asc
GET    /api/v1/users?page=2&limit=25
GET    /api/v1/users?fields=name,email
GET    /api/v1/users?search=john
GET    /api/v1/users?created_after=2024-01-01

# Versioning
GET    /api/v1/users
GET    /api/v2/users
# Or via header
GET    /api/users
Accept: application/vnd.api.v2+json

# Bad REST URL patterns (avoid)
GET    /api/getUsers               # Verb in URL
POST   /api/createUser             # Verb in URL
GET    /api/user/delete/123        # Action in URL
GET    /api/Users                  # Uppercase
GET    /api/user_list              # Underscore
```
::

### REST API Request Example

::code-preview
---
class: "[&>div]:*:my-0"
---
Complete REST API request anatomy.

#code
```http
POST /api/v1/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
User-Agent: MyApp/1.0
Cache-Control: no-cache
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
Content-Length: 95

{
  "name": "John Smith",
  "email": "john@example.com",
  "role": "user",
  "active": true
}
```
::

### REST API Response Example

::code-preview
---
class: "[&>div]:*:my-0"
---
Complete REST API response anatomy.

#code
```http
HTTP/1.1 201 Created
Content-Type: application/json
Location: /api/v1/users/124
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640000000
Cache-Control: no-store
Date: Mon, 01 Jan 2024 12:00:00 GMT
Content-Length: 156

{
  "id": 124,
  "name": "John Smith",
  "email": "john@example.com",
  "role": "user",
  "active": true,
  "created_at": "2024-01-01T12:00:00Z",
  "links": {
    "self": "/api/v1/users/124",
    "orders": "/api/v1/users/124/orders"
  }
}
```
::

---

## SOAP API

::code-preview
---
class: "[&>div]:*:my-0"
---
SOAP API request and response structure.

#code
```xml
<!-- SOAP Request -->
POST /ws/users HTTP/1.1
Host: api.example.com
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://example.com/GetUser"

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:usr="http://example.com/users">
  <soap:Header>
    <usr:AuthToken>abc123token</usr:AuthToken>
  </soap:Header>
  <soap:Body>
    <usr:GetUserRequest>
      <usr:UserId>123</usr:UserId>
    </usr:GetUserRequest>
  </soap:Body>
</soap:Envelope>

<!-- SOAP Response -->
HTTP/1.1 200 OK
Content-Type: text/xml; charset=utf-8

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:usr="http://example.com/users">
  <soap:Body>
    <usr:GetUserResponse>
      <usr:User>
        <usr:Id>123</usr:Id>
        <usr:Name>John Smith</usr:Name>
        <usr:Email>john@example.com</usr:Email>
      </usr:User>
    </usr:GetUserResponse>
  </soap:Body>
</soap:Envelope>
```
::

### REST vs SOAP Comparison

| Feature              | REST                          | SOAP                           |
| -------------------- | ----------------------------- | ------------------------------ |
| Protocol             | HTTP/HTTPS                    | HTTP, SMTP, TCP                |
| Data format          | JSON, XML, others             | XML only                       |
| Standards            | Loose guidelines              | Strict WS-* standards          |
| State                | Stateless                     | Can be stateful                |
| Performance          | Lightweight, faster           | Heavier due to XML overhead    |
| Security             | HTTPS, OAuth, JWT             | WS-Security, built-in          |
| Caching              | Native HTTP caching           | No native caching              |
| Error handling       | HTTP status codes             | SOAP Fault element             |
| WSDL                 | Not required (OpenAPI/Swagger)| Required for contract           |
| Use case             | Web, mobile, microservices    | Enterprise, banking, legacy    |
| Learning curve       | Low                           | High                           |

---

## GraphQL API

::code-preview
---
class: "[&>div]:*:my-0"
---
GraphQL request and response structure.

#code
```
# GraphQL Query (read data)
POST /graphql HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer <token>

{
  "query": "{ user(id: 123) { name email orders { id total } } }"
}

# Response
{
  "data": {
    "user": {
      "name": "John Smith",
      "email": "john@example.com",
      "orders": [
        { "id": 1, "total": 99.99 },
        { "id": 2, "total": 149.50 }
      ]
    }
  }
}

# GraphQL Mutation (write data)
{
  "query": "mutation { createUser(input: { name: \"Jane\", email: \"jane@example.com\" }) { id name } }"
}

# GraphQL Subscription (real-time)
{
  "query": "subscription { newMessage { id text sender } }"
}

# Query with variables
{
  "query": "query GetUser($id: ID!) { user(id: $id) { name email } }",
  "variables": { "id": "123" }
}

# Query with fragments
{
  "query": "{ user(id: 123) { ...UserFields } } fragment UserFields on User { name email role }"
}
```
::

### REST vs GraphQL Comparison

| Feature          | REST                              | GraphQL                            |
| ---------------- | --------------------------------- | ---------------------------------- |
| Endpoints        | Multiple (`/users`, `/orders`)    | Single (`/graphql`)                |
| Data fetching    | Fixed data per endpoint           | Client specifies exact fields      |
| Over-fetching    | Common problem                    | Eliminated                         |
| Under-fetching   | Requires multiple requests        | Single query gets all needed data  |
| Versioning       | `/v1/`, `/v2/`                    | Schema evolution, no versioning    |
| Caching          | HTTP caching built-in             | Complex, needs custom solutions    |
| File uploads     | Native support                    | Requires multipart spec            |
| Real-time        | WebSocket / SSE separately        | Subscriptions built-in             |
| Error handling   | HTTP status codes                 | Always 200, errors in response body|
| Learning curve   | Low                               | Medium                             |

---

## How HTTP Works

### HTTP Communication Flow

::code-preview
---
class: "[&>div]:*:my-0"
---
Step-by-step HTTP request lifecycle.

#code
```
Step 1: DNS Resolution
┌──────────┐    DNS Query     ┌──────────┐
│  Client   │ ──────────────► │DNS Server │
│ (Browser) │ ◄────────────── │           │
└──────────┘  IP: 93.184.216  └──────────┘

Step 2: TCP Connection (Three-Way Handshake)
┌──────────┐     SYN          ┌──────────┐
│  Client   │ ──────────────► │  Server   │
│           │ ◄────────────── │           │
│           │     SYN-ACK     │           │
│           │ ──────────────► │           │
└──────────┘     ACK          └──────────┘

Step 3: TLS Handshake (HTTPS only)
┌──────────┐   ClientHello    ┌──────────┐
│  Client   │ ──────────────► │  Server   │
│           │ ◄────────────── │           │
│           │   ServerHello   │           │
│           │   Certificate   │           │
│           │ ──────────────► │           │
│           │   Key Exchange  │           │
│           │ ◄────────────── │           │
└──────────┘   Finished       └──────────┘

Step 4: HTTP Request
┌──────────┐   HTTP Request   ┌──────────┐
│  Client   │ ──────────────► │  Server   │
│           │                 │           │
│           │   GET /page     │           │
│           │   Host: ...     │           │
│           │   Headers...    │           │
└──────────┘                  └──────────┘

Step 5: Server Processing
┌──────────┐                  ┌──────────┐
│  Server   │ ──► Route       │          │
│           │ ──► Middleware   │ Backend  │
│           │ ──► Controller   │  Logic   │
│           │ ──► Database     │          │
│           │ ◄── Response     │          │
└──────────┘                  └──────────┘

Step 6: HTTP Response
┌──────────┐  HTTP Response   ┌──────────┐
│  Client   │ ◄────────────── │  Server   │
│           │                 │           │
│           │  200 OK         │           │
│           │  Headers...     │           │
│           │  Body...        │           │
└──────────┘                  └──────────┘

Step 7: TCP Connection Close (Four-Way Handshake)
┌──────────┐     FIN          ┌──────────┐
│  Client   │ ──────────────► │  Server   │
│           │ ◄────────────── │           │
│           │     ACK         │           │
│           │ ◄────────────── │           │
│           │     FIN         │           │
│           │ ──────────────► │           │
└──────────┘     ACK          └──────────┘
```
::

### HTTP Request Structure

::code-preview
---
class: "[&>div]:*:my-0"
---
Anatomy of an HTTP request.

#code
```http
# Request Line
METHOD /path/to/resource?query=value HTTP/1.1

# Headers (key: value pairs)
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/json
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 42
Authorization: Bearer <token>
Cookie: session=abc123; theme=dark
Referer: https://www.example.com/previous-page
Origin: https://www.example.com
Cache-Control: no-cache
X-Requested-With: XMLHttpRequest
X-Forwarded-For: 203.0.113.195

# Blank line (separates headers from body)

# Request Body (for POST, PUT, PATCH)
{"username": "admin", "password": "secret"}
```
::

### HTTP Response Structure

::code-preview
---
class: "[&>div]:*:my-0"
---
Anatomy of an HTTP response.

#code
```http
# Status Line
HTTP/1.1 200 OK

# Response Headers
Date: Mon, 01 Jan 2024 12:00:00 GMT
Server: nginx/1.24.0
Content-Type: application/json; charset=utf-8
Content-Length: 256
Content-Encoding: gzip
Connection: keep-alive
Cache-Control: max-age=3600, public
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
Last-Modified: Sun, 31 Dec 2023 23:59:59 GMT
Set-Cookie: session=xyz789; Path=/; HttpOnly; Secure; SameSite=Strict
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
Access-Control-Allow-Origin: https://www.example.com
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95

# Blank line

# Response Body
{
  "status": "success",
  "data": {
    "id": 1,
    "name": "John Smith",
    "email": "john@example.com"
  }
}
```
::

### HTTP Versions Comparison

| Feature                | HTTP/1.0          | HTTP/1.1               | HTTP/2                  | HTTP/3                  |
| ---------------------- | ----------------- | ---------------------- | ----------------------- | ----------------------- |
| Year                   | 1996              | 1997                   | 2015                    | 2022                    |
| Connection             | Close after each  | Keep-alive (persistent)| Multiplexed             | Multiplexed             |
| Protocol               | TCP               | TCP                    | TCP                     | QUIC (UDP)              |
| Pipelining             | No                | Yes (limited)          | Yes (streams)           | Yes (streams)           |
| Header compression     | No                | No                     | HPACK                   | QPACK                   |
| Server push            | No                | No                     | Yes                     | Yes                     |
| Stream prioritization  | No                | No                     | Yes                     | Yes                     |
| Head-of-line blocking  | Yes               | Yes                    | At TCP level            | Eliminated              |
| TLS required           | No                | No                     | Practically yes         | Yes (built-in)          |
| Binary protocol        | No                | No                     | Yes                     | Yes                     |
| Concurrent requests    | 1 per connection  | 1 per connection (HOL) | Unlimited (streams)     | Unlimited (streams)     |

---

## HTTP Methods (Verbs)

HTTP methods define the action to perform on a resource.

### GET

Retrieve data from the server. Should be **safe** (no side effects) and **idempotent** (same result on repeated calls).

::code-preview
---
class: "[&>div]:*:my-0"
---
GET method examples.

#code
```http
# Basic GET request
GET /api/users HTTP/1.1
Host: api.example.com
Accept: application/json
Authorization: Bearer <token>

# GET with query parameters
GET /api/users?page=2&limit=25&sort=name&order=asc HTTP/1.1
Host: api.example.com

# GET specific resource
GET /api/users/123 HTTP/1.1
Host: api.example.com

# GET with conditional headers
GET /api/users/123 HTTP/1.1
Host: api.example.com
If-None-Match: "etag-value"
If-Modified-Since: Mon, 01 Jan 2024 00:00:00 GMT

# cURL examples
curl -X GET https://api.example.com/users
curl -X GET "https://api.example.com/users?page=1&limit=10"
curl -H "Authorization: Bearer <token>" https://api.example.com/users/123
```
::

| Property       | Value     |
| -------------- | --------- |
| Request Body   | No        |
| Response Body  | Yes       |
| Safe           | Yes       |
| Idempotent     | Yes       |
| Cacheable      | Yes       |

### POST

Submit data to create a new resource. **Not idempotent** — repeated calls create multiple resources.

::code-preview
---
class: "[&>div]:*:my-0"
---
POST method examples.

#code
```http
# Create new resource
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer <token>

{
  "name": "John Smith",
  "email": "john@example.com",
  "password": "secureP@ss123"
}

# Response
HTTP/1.1 201 Created
Location: /api/users/124
Content-Type: application/json

{
  "id": 124,
  "name": "John Smith",
  "email": "john@example.com",
  "created_at": "2024-01-01T12:00:00Z"
}

# POST form data
POST /api/login HTTP/1.1
Host: api.example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret

# POST multipart (file upload)
POST /api/upload HTTP/1.1
Host: api.example.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="document.pdf"
Content-Type: application/pdf

<binary file data>
------Boundary--

# cURL examples
curl -X POST https://api.example.com/users \
  -H "Content-Type: application/json" \
  -d '{"name":"John","email":"john@example.com"}'

curl -X POST https://api.example.com/upload \
  -F "file=@document.pdf"

curl -X POST https://api.example.com/login \
  -d "username=admin&password=secret"
```
::

| Property       | Value     |
| -------------- | --------- |
| Request Body   | Yes       |
| Response Body  | Yes       |
| Safe           | No        |
| Idempotent     | No        |
| Cacheable      | Rarely    |

### PUT

Replace an entire resource or create it if it doesn't exist. **Idempotent** — repeated calls produce the same result.

::code-preview
---
class: "[&>div]:*:my-0"
---
PUT method examples.

#code
```http
# Update entire resource (must include ALL fields)
PUT /api/users/123 HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer <token>

{
  "name": "John Smith Updated",
  "email": "john.updated@example.com",
  "role": "admin",
  "active": true,
  "phone": "+1234567890"
}

# Response
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 123,
  "name": "John Smith Updated",
  "email": "john.updated@example.com",
  "role": "admin",
  "active": true,
  "phone": "+1234567890",
  "updated_at": "2024-01-01T12:30:00Z"
}

# Create if not exists (upsert)
PUT /api/users/999 HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "name": "New User",
  "email": "new@example.com"
}

# Response (created)
HTTP/1.1 201 Created

# cURL
curl -X PUT https://api.example.com/users/123 \
  -H "Content-Type: application/json" \
  -d '{"name":"Updated Name","email":"updated@example.com","role":"user","active":true}'
```
::

| Property       | Value     |
| -------------- | --------- |
| Request Body   | Yes       |
| Response Body  | Yes       |
| Safe           | No        |
| Idempotent     | Yes       |
| Cacheable      | No        |

### PATCH

Partially update a resource. Only send the fields that need to change. **Not necessarily idempotent**.

::code-preview
---
class: "[&>div]:*:my-0"
---
PATCH method examples.

#code
```http
# Partial update (only changed fields)
PATCH /api/users/123 HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer <token>

{
  "email": "newemail@example.com"
}

# Response
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 123,
  "name": "John Smith",
  "email": "newemail@example.com",
  "role": "user",
  "updated_at": "2024-01-01T12:45:00Z"
}

# JSON Patch format (RFC 6902)
PATCH /api/users/123 HTTP/1.1
Content-Type: application/json-patch+json

[
  { "op": "replace", "path": "/email", "value": "new@example.com" },
  { "op": "add", "path": "/phone", "value": "+1234567890" },
  { "op": "remove", "path": "/nickname" }
]

# JSON Merge Patch (RFC 7396)
PATCH /api/users/123 HTTP/1.1
Content-Type: application/merge-patch+json

{
  "email": "new@example.com",
  "nickname": null
}

# cURL
curl -X PATCH https://api.example.com/users/123 \
  -H "Content-Type: application/json" \
  -d '{"email":"newemail@example.com"}'
```
::

| Property       | Value       |
| -------------- | ----------- |
| Request Body   | Yes         |
| Response Body  | Yes         |
| Safe           | No          |
| Idempotent     | Not always  |
| Cacheable      | No          |

### PUT vs PATCH Comparison

| Aspect             | PUT                                | PATCH                              |
| ------------------ | ---------------------------------- | ---------------------------------- |
| Update scope       | Full resource replacement          | Partial update only                |
| Required fields    | All fields must be sent            | Only changed fields                |
| Missing fields     | Set to null/default                | Remain unchanged                   |
| Idempotent         | Always                             | Not guaranteed                     |
| Use case           | Complete resource replacement      | Small modifications                |
| Bandwidth          | Higher (full payload)              | Lower (partial payload)            |

### DELETE

Remove a resource from the server. **Idempotent** — deleting the same resource twice produces the same result.

::code-preview
---
class: "[&>div]:*:my-0"
---
DELETE method examples.

#code
```http
# Delete a resource
DELETE /api/users/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer <token>

# Response (no content)
HTTP/1.1 204 No Content

# Response (with confirmation)
HTTP/1.1 200 OK
Content-Type: application/json

{
  "message": "User 123 deleted successfully",
  "deleted_at": "2024-01-01T13:00:00Z"
}

# Delete with body (some APIs)
DELETE /api/items HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "ids": [1, 2, 3, 4, 5]
}

# Soft delete (common pattern)
# Internally marks as deleted, not actually removed
DELETE /api/users/123 HTTP/1.1
# Returns 200, user.deleted = true

# cURL
curl -X DELETE https://api.example.com/users/123 \
  -H "Authorization: Bearer <token>"

curl -X DELETE https://api.example.com/items \
  -H "Content-Type: application/json" \
  -d '{"ids":[1,2,3]}'
```
::

| Property       | Value     |
| -------------- | --------- |
| Request Body   | Optional  |
| Response Body  | Optional  |
| Safe           | No        |
| Idempotent     | Yes       |
| Cacheable      | No        |

### HEAD

Identical to GET but returns **only headers**, no body. Used to check if a resource exists or get metadata.

::code-preview
---
class: "[&>div]:*:my-0"
---
HEAD method examples.

#code
```http
# Check if resource exists
HEAD /api/users/123 HTTP/1.1
Host: api.example.com

# Response (no body)
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 256
Last-Modified: Mon, 01 Jan 2024 12:00:00 GMT
ETag: "abc123"

# Check file size before downloading
HEAD /files/large-document.pdf HTTP/1.1
Host: cdn.example.com

# Response
HTTP/1.1 200 OK
Content-Length: 52428800
Content-Type: application/pdf
Accept-Ranges: bytes

# cURL
curl -I https://api.example.com/users/123
curl --head https://cdn.example.com/file.pdf
```
::

| Property       | Value     |
| -------------- | --------- |
| Request Body   | No        |
| Response Body  | No        |
| Safe           | Yes       |
| Idempotent     | Yes       |
| Cacheable      | Yes       |

### OPTIONS

Describes the communication options for the target resource. Used in **CORS preflight** requests.

::code-preview
---
class: "[&>div]:*:my-0"
---
OPTIONS method examples.

#code
```http
# Discover supported methods
OPTIONS /api/users HTTP/1.1
Host: api.example.com

# Response
HTTP/1.1 204 No Content
Allow: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
Accept-Patch: application/json-patch+json

# CORS Preflight Request (sent automatically by browser)
OPTIONS /api/users HTTP/1.1
Host: api.example.com
Origin: https://frontend.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization

# CORS Preflight Response
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://frontend.example.com
Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400

# cURL
curl -X OPTIONS https://api.example.com/users -i
curl -X OPTIONS https://api.example.com/users \
  -H "Origin: https://frontend.example.com" \
  -H "Access-Control-Request-Method: POST" -i
```
::

| Property       | Value     |
| -------------- | --------- |
| Request Body   | No        |
| Response Body  | Optional  |
| Safe           | Yes       |
| Idempotent     | Yes       |
| Cacheable      | No        |

### TRACE

Echoes back the received request for debugging. Usually **disabled** for security reasons.

::code-preview
---
class: "[&>div]:*:my-0"
---
TRACE method examples.

#code
```http
# TRACE request
TRACE /api/users HTTP/1.1
Host: api.example.com
X-Custom-Header: test-value

# Response (echoes back the request)
HTTP/1.1 200 OK
Content-Type: message/http

TRACE /api/users HTTP/1.1
Host: api.example.com
X-Custom-Header: test-value

# Security concern: Cross-Site Tracing (XST)
# TRACE can be used to steal HttpOnly cookies via XSS
# An XSS payload can make a TRACE request and read the response
# which includes cookies in the echoed headers

# Should be DISABLED on all production servers
# Apache: TraceEnable off
# Nginx: Blocked by default
# IIS: Disable via Request Filtering

# cURL
curl -X TRACE https://api.example.com/ -i
```
::

| Property       | Value     |
| -------------- | --------- |
| Request Body   | No        |
| Response Body  | Yes       |
| Safe           | Yes       |
| Idempotent     | Yes       |
| Cacheable      | No        |

### CONNECT

Establishes a tunnel to the server, typically for HTTPS proxying.

::code-preview
---
class: "[&>div]:*:my-0"
---
CONNECT method examples.

#code
```http
# Establish tunnel through proxy
CONNECT www.example.com:443 HTTP/1.1
Host: www.example.com:443
Proxy-Authorization: Basic dXNlcjpwYXNz

# Response
HTTP/1.1 200 Connection Established

# After tunnel is established, TLS handshake occurs
# Then all traffic flows through the encrypted tunnel

# Used by:
# - HTTP proxies for HTTPS connections
# - VPN tunneling
# - WebSocket upgrades through proxies

# Security concern:
# - Can be abused to tunnel arbitrary traffic
# - Should be restricted to port 443
```
::

| Property       | Value     |
| -------------- | --------- |
| Request Body   | No        |
| Response Body  | No        |
| Safe           | No        |
| Idempotent     | No        |
| Cacheable      | No        |

### HTTP Methods Complete Reference

| Method    | Purpose                   | Safe | Idempotent | Body (Request) | Body (Response) | Cacheable |
| --------- | ------------------------- | ---- | ---------- | -------------- | --------------- | --------- |
| `GET`     | Retrieve resource         | ✅   | ✅         | ❌             | ✅              | ✅        |
| `POST`    | Create resource           | ❌   | ❌         | ✅             | ✅              | ❌        |
| `PUT`     | Replace resource          | ❌   | ✅         | ✅             | ✅              | ❌        |
| `PATCH`   | Partial update            | ❌   | ❌         | ✅             | ✅              | ❌        |
| `DELETE`  | Delete resource           | ❌   | ✅         | Optional       | Optional        | ❌        |
| `HEAD`    | Get headers only          | ✅   | ✅         | ❌             | ❌              | ✅        |
| `OPTIONS` | Get supported methods     | ✅   | ✅         | ❌             | Optional        | ❌        |
| `TRACE`   | Echo request (debug)      | ✅   | ✅         | ❌             | ✅              | ❌        |
| `CONNECT` | Establish tunnel          | ❌   | ❌         | ❌             | ❌              | ❌        |

---

## HTTP Headers Deep Dive

### Request Headers

| Header                    | Purpose                                | Example                                        |
| ------------------------- | -------------------------------------- | ---------------------------------------------- |
| `Host`                    | Target hostname (required HTTP/1.1)    | `Host: www.example.com`                        |
| `User-Agent`              | Client software identification         | `User-Agent: Mozilla/5.0 ...`                  |
| `Accept`                  | Acceptable response media types        | `Accept: application/json`                     |
| `Accept-Language`         | Preferred languages                    | `Accept-Language: en-US,en;q=0.9`              |
| `Accept-Encoding`         | Acceptable compression                 | `Accept-Encoding: gzip, deflate, br`           |
| `Accept-Charset`          | Acceptable character sets              | `Accept-Charset: utf-8`                        |
| `Authorization`           | Authentication credentials             | `Authorization: Bearer <token>`                |
| `Cookie`                  | Stored cookies                         | `Cookie: session=abc123`                       |
| `Content-Type`            | Media type of request body             | `Content-Type: application/json`               |
| `Content-Length`           | Size of request body in bytes          | `Content-Length: 256`                           |
| `Origin`                  | Request origin (CORS)                  | `Origin: https://frontend.example.com`         |
| `Referer`                 | Previous page URL                      | `Referer: https://example.com/page`            |
| `If-None-Match`           | Conditional (ETag comparison)          | `If-None-Match: "etag123"`                     |
| `If-Modified-Since`       | Conditional (date comparison)          | `If-Modified-Since: Mon, 01 Jan 2024 ...`      |
| `Cache-Control`           | Caching directives                     | `Cache-Control: no-cache`                      |
| `Connection`              | Connection management                  | `Connection: keep-alive`                       |
| `X-Forwarded-For`         | Original client IP (behind proxy)      | `X-Forwarded-For: 203.0.113.195`              |
| `X-Forwarded-Host`        | Original host (behind proxy)           | `X-Forwarded-Host: example.com`               |
| `X-Forwarded-Proto`       | Original protocol (behind proxy)       | `X-Forwarded-Proto: https`                     |
| `X-Requested-With`        | Ajax request indicator                 | `X-Requested-With: XMLHttpRequest`             |

### Response Headers

| Header                        | Purpose                              | Example                                        |
| ----------------------------- | ------------------------------------ | ---------------------------------------------- |
| `Content-Type`                | Media type of response body          | `Content-Type: application/json; charset=utf-8` |
| `Content-Length`              | Response body size in bytes          | `Content-Length: 1024`                           |
| `Content-Encoding`            | Compression method                   | `Content-Encoding: gzip`                         |
| `Content-Disposition`         | Attachment / inline display          | `Content-Disposition: attachment; filename="f.pdf"` |
| `Date`                        | Response generation time             | `Date: Mon, 01 Jan 2024 12:00:00 GMT`            |
| `Server`                      | Server software                      | `Server: nginx/1.24.0`                           |
| `Set-Cookie`                  | Set cookie in browser                | `Set-Cookie: session=xyz; HttpOnly; Secure`      |
| `Cache-Control`               | Caching directives                   | `Cache-Control: max-age=3600, public`            |
| `ETag`                        | Entity tag for caching               | `ETag: "abc123"`                                 |
| `Last-Modified`               | Last resource modification date      | `Last-Modified: Sun, 31 Dec 2023 ...`            |
| `Location`                    | Redirect URL                         | `Location: /api/users/124`                       |
| `Expires`                     | Response expiration date             | `Expires: Mon, 01 Jan 2024 13:00:00 GMT`         |
| `Allow`                       | Supported HTTP methods               | `Allow: GET, POST, PUT, DELETE`                  |
| `WWW-Authenticate`            | Authentication method required       | `WWW-Authenticate: Bearer`                       |
| `Retry-After`                 | When to retry (rate limiting)        | `Retry-After: 120`                               |

### Security Headers

| Header                          | Purpose                                  | Recommended Value                              |
| ------------------------------- | ---------------------------------------- | ---------------------------------------------- |
| `Strict-Transport-Security`     | Force HTTPS                              | `max-age=31536000; includeSubDomains; preload` |
| `Content-Security-Policy`       | Control allowed content sources          | `default-src 'self'; script-src 'self'`        |
| `X-Content-Type-Options`        | Prevent MIME sniffing                    | `nosniff`                                      |
| `X-Frame-Options`               | Prevent clickjacking                     | `DENY` or `SAMEORIGIN`                         |
| `X-XSS-Protection`              | XSS filter (legacy)                      | `1; mode=block`                                |
| `Referrer-Policy`               | Control referrer information             | `strict-origin-when-cross-origin`              |
| `Permissions-Policy`            | Control browser features                 | `camera=(), microphone=(), geolocation=()`     |
| `Cross-Origin-Opener-Policy`    | Isolate browsing context                 | `same-origin`                                  |
| `Cross-Origin-Resource-Policy`  | Control cross-origin resource loading    | `same-origin`                                  |
| `Cross-Origin-Embedder-Policy`  | Require CORP/CORS for subresources       | `require-corp`                                 |

### Content-Type Values

| Content-Type                                | Use Case                        |
| ------------------------------------------- | ------------------------------- |
| `application/json`                          | JSON data (most APIs)           |
| `application/xml`                           | XML data                        |
| `application/x-www-form-urlencoded`         | HTML form data                  |
| `multipart/form-data`                       | File uploads                    |
| `text/html`                                 | HTML pages                      |
| `text/plain`                                | Plain text                      |
| `text/css`                                  | CSS stylesheets                 |
| `text/javascript`                           | JavaScript                      |
| `application/octet-stream`                  | Binary data                     |
| `application/pdf`                           | PDF documents                   |
| `image/jpeg`                                | JPEG images                     |
| `image/png`                                 | PNG images                      |
| `image/svg+xml`                             | SVG images                      |
| `application/graphql`                       | GraphQL queries                 |
| `application/grpc`                          | gRPC calls                      |
| `text/event-stream`                         | Server-Sent Events              |
| `application/json-patch+json`               | JSON Patch (RFC 6902)           |
| `application/merge-patch+json`              | JSON Merge Patch (RFC 7396)     |

---

## HTTP Status Codes

### Status Code Categories

| Range       | Category        | Description                                    |
| ----------- | --------------- | ---------------------------------------------- |
| `1xx`       | Informational   | Request received, processing continues         |
| `2xx`       | Success         | Request successfully received and accepted     |
| `3xx`       | Redirection     | Further action needed to complete request      |
| `4xx`       | Client Error    | Request contains bad syntax or cannot be fulfilled |
| `5xx`       | Server Error    | Server failed to fulfill valid request         |

---

### 1xx Informational

The server has received the request headers and the client should proceed.

| Code  | Status                    | Description                                                     |
| ----- | ------------------------- | --------------------------------------------------------------- |
| `100` | Continue                  | Server received headers; client should send body                |
| `101` | Switching Protocols       | Server is switching to protocol requested by client (WebSocket) |
| `102` | Processing (WebDAV)       | Server received and is processing, no response yet              |
| `103` | Early Hints               | Server sends preliminary headers before final response          |

::code-preview
---
class: "[&>div]:*:my-0"
---
1xx status code examples.

#code
```http
# 100 Continue
# Client sends large body, checks if server will accept
POST /api/upload HTTP/1.1
Host: api.example.com
Content-Length: 1073741824
Expect: 100-continue

# Server response
HTTP/1.1 100 Continue
# Client now sends the body

# 101 Switching Protocols (WebSocket upgrade)
GET /ws HTTP/1.1
Host: api.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

# 103 Early Hints
HTTP/1.1 103 Early Hints
Link: </style.css>; rel=preload; as=style
Link: </script.js>; rel=preload; as=script

HTTP/1.1 200 OK
Content-Type: text/html
# Browser started loading CSS/JS before final response arrived
```
::

---

### 2xx Success

The request was successfully received, understood, and accepted.

| Code  | Status                          | Description                                                      |
| ----- | ------------------------------- | ---------------------------------------------------------------- |
| `200` | OK                              | Standard success response                                        |
| `201` | Created                         | Resource successfully created (POST)                             |
| `202` | Accepted                        | Request accepted for processing (async)                          |
| `203` | Non-Authoritative Information   | Response modified by proxy                                       |
| `204` | No Content                      | Success but no response body (DELETE)                            |
| `205` | Reset Content                   | Reset the document/form that sent the request                    |
| `206` | Partial Content                 | Partial resource returned (range request)                        |
| `207` | Multi-Status (WebDAV)           | Multiple status codes for multiple operations                    |
| `208` | Already Reported (WebDAV)       | Members already enumerated in previous response                  |
| `226` | IM Used                         | Server fulfilled GET with instance-manipulations                 |

::code-preview
---
class: "[&>div]:*:my-0"
---
2xx status code examples.

#code
```http
# 200 OK - Successful GET
HTTP/1.1 200 OK
Content-Type: application/json

{"id": 1, "name": "John"}

# 201 Created - Successful POST
HTTP/1.1 201 Created
Location: /api/users/124
Content-Type: application/json

{"id": 124, "name": "John", "created_at": "2024-01-01T12:00:00Z"}

# 202 Accepted - Async processing
HTTP/1.1 202 Accepted
Content-Type: application/json
Location: /api/jobs/789

{"message": "Report generation started", "job_id": 789, "status_url": "/api/jobs/789"}

# 204 No Content - Successful DELETE
HTTP/1.1 204 No Content

# 206 Partial Content - Range request (video streaming, large downloads)
GET /video.mp4 HTTP/1.1
Range: bytes=0-1023

HTTP/1.1 206 Partial Content
Content-Range: bytes 0-1023/1048576
Content-Length: 1024
Content-Type: video/mp4

<first 1024 bytes>

# 207 Multi-Status (WebDAV batch)
HTTP/1.1 207 Multi-Status
Content-Type: application/xml

<?xml version="1.0"?>
<multistatus>
  <response>
    <href>/file1</href>
    <status>HTTP/1.1 200 OK</status>
  </response>
  <response>
    <href>/file2</href>
    <status>HTTP/1.1 404 Not Found</status>
  </response>
</multistatus>
```
::

---

### 3xx Redirection

The client must take additional action to complete the request.

| Code  | Status                    | Description                                                        |
| ----- | ------------------------- | ------------------------------------------------------------------ |
| `300` | Multiple Choices          | Multiple options available for the resource                        |
| `301` | Moved Permanently        | Resource permanently moved to new URL (cached by browsers)         |
| `302` | Found (Temporary Redirect)| Resource temporarily at different URL                              |
| `303` | See Other                 | Redirect to another resource using GET                             |
| `304` | Not Modified              | Resource hasn't changed (use cached version)                       |
| `305` | Use Proxy (Deprecated)    | Must access through proxy                                          |
| `307` | Temporary Redirect        | Same as 302 but preserves HTTP method                              |
| `308` | Permanent Redirect        | Same as 301 but preserves HTTP method                              |

::code-preview
---
class: "[&>div]:*:my-0"
---
3xx status code examples.

#code
```http
# 301 Moved Permanently
# Browser caches this redirect permanently
# Search engines update their index
HTTP/1.1 301 Moved Permanently
Location: https://www.new-domain.com/page

# Use case: Domain migration, HTTP→HTTPS
# Method may change to GET (historical behavior)

# 302 Found (Temporary Redirect)
# Browser does NOT cache
# Search engines keep old URL
HTTP/1.1 302 Found
Location: https://www.example.com/temporary-page

# Use case: A/B testing, maintenance pages
# Method may change to GET (historical behavior)

# 303 See Other
# Always changes method to GET
# Used after POST to redirect to result page
POST /api/orders HTTP/1.1
Content-Type: application/json
{"product": "item1"}

HTTP/1.1 303 See Other
Location: /api/orders/456

# Client follows up with GET /api/orders/456

# 304 Not Modified
GET /api/users/123 HTTP/1.1
If-None-Match: "etag-abc123"

HTTP/1.1 304 Not Modified
ETag: "etag-abc123"
# No body sent, client uses cached version

# 307 Temporary Redirect
# Preserves original HTTP method (POST stays POST)
HTTP/1.1 307 Temporary Redirect
Location: https://api.example.com/v2/users

# 308 Permanent Redirect
# Preserves original HTTP method (POST stays POST)
# Browser caches permanently
HTTP/1.1 308 Permanent Redirect
Location: https://api.example.com/v2/users
```
::

### Redirect Comparison

| Code  | Permanent | Method Preserved | Cached  | Use Case                           |
| ----- | --------- | ---------------- | ------- | ---------------------------------- |
| `301` | Yes       | No (may → GET)   | Yes     | Domain/URL migration               |
| `302` | No        | No (may → GET)   | No      | Temporary redirect                 |
| `303` | No        | No (always GET)  | No      | POST → GET redirect (PRG pattern)  |
| `307` | No        | Yes              | No      | Temporary redirect, keep method    |
| `308` | Yes       | Yes              | Yes     | Permanent redirect, keep method    |

---

### 4xx Client Errors

The request contains bad syntax or cannot be fulfilled by the server.

| Code  | Status                          | Description                                                       |
| ----- | ------------------------------- | ----------------------------------------------------------------- |
| `400` | Bad Request                     | Malformed request syntax, invalid parameters                      |
| `401` | Unauthorized                    | Authentication required or failed                                 |
| `402` | Payment Required                | Reserved for future use (digital payments)                        |
| `403` | Forbidden                       | Server understood but refuses to authorize                        |
| `404` | Not Found                       | Resource does not exist                                           |
| `405` | Method Not Allowed              | HTTP method not supported for this resource                       |
| `406` | Not Acceptable                  | Cannot produce response matching Accept headers                   |
| `407` | Proxy Authentication Required   | Authentication required by proxy                                  |
| `408` | Request Timeout                 | Server timed out waiting for the request                          |
| `409` | Conflict                        | Request conflicts with current resource state                     |
| `410` | Gone                            | Resource permanently removed (unlike 404)                         |
| `411` | Length Required                  | Content-Length header required                                     |
| `412` | Precondition Failed             | Precondition in headers evaluated to false                        |
| `413` | Payload Too Large               | Request body exceeds server limits                                |
| `414` | URI Too Long                    | Request URI exceeds server limits                                 |
| `415` | Unsupported Media Type          | Content-Type not supported                                        |
| `416` | Range Not Satisfiable           | Requested range cannot be served                                  |
| `417` | Expectation Failed              | Expect header requirement cannot be met                           |
| `418` | I'm a Teapot (RFC 2324)        | Easter egg — teapot cannot brew coffee                            |
| `421` | Misdirected Request             | Request directed to wrong server                                  |
| `422` | Unprocessable Entity (WebDAV)   | Request well-formed but semantically incorrect                    |
| `423` | Locked (WebDAV)                 | Resource is locked                                                |
| `424` | Failed Dependency (WebDAV)      | Failed due to failure of previous request                         |
| `425` | Too Early                       | Server unwilling to process potentially replayed request          |
| `426` | Upgrade Required                | Client should switch to different protocol                        |
| `428` | Precondition Required           | Request must be conditional (prevents lost updates)               |
| `429` | Too Many Requests               | Rate limit exceeded                                               |
| `431` | Request Header Fields Too Large | Headers exceed server limits                                      |
| `451` | Unavailable For Legal Reasons   | Resource blocked for legal reasons (censorship)                   |

::code-preview
---
class: "[&>div]:*:my-0"
---
4xx status code examples.

#code
```http
# 400 Bad Request
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "Bad Request",
  "message": "Invalid JSON in request body",
  "details": [
    {"field": "email", "error": "Invalid email format"},
    {"field": "age", "error": "Must be a positive integer"}
  ]
}

# 401 Unauthorized (authentication required)
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api"
Content-Type: application/json

{
  "error": "Unauthorized",
  "message": "Invalid or expired authentication token"
}

# 403 Forbidden (authenticated but not authorized)
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Forbidden",
  "message": "You do not have permission to access this resource",
  "required_role": "admin"
}

# 401 vs 403:
# 401 = "Who are you?" (not authenticated)
# 403 = "I know who you are, but you can't do this" (not authorized)

# 404 Not Found
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "error": "Not Found",
  "message": "User with ID 999 not found"
}

# 405 Method Not Allowed
HTTP/1.1 405 Method Not Allowed
Allow: GET, POST
Content-Type: application/json

{
  "error": "Method Not Allowed",
  "message": "DELETE is not supported for /api/users",
  "allowed_methods": ["GET", "POST"]
}

# 409 Conflict
HTTP/1.1 409 Conflict
Content-Type: application/json

{
  "error": "Conflict",
  "message": "User with email john@example.com already exists",
  "conflicting_field": "email"
}

# 410 Gone
HTTP/1.1 410 Gone
Content-Type: application/json

{
  "error": "Gone",
  "message": "This API endpoint has been permanently removed. Use /api/v2/users instead."
}

# 413 Payload Too Large
HTTP/1.1 413 Payload Too Large
Content-Type: application/json
Retry-After: 3600

{
  "error": "Payload Too Large",
  "message": "Request body exceeds maximum size of 10MB",
  "max_size": "10485760"
}

# 415 Unsupported Media Type
HTTP/1.1 415 Unsupported Media Type
Content-Type: application/json

{
  "error": "Unsupported Media Type",
  "message": "Content-Type 'text/xml' is not supported. Use 'application/json'",
  "supported_types": ["application/json"]
}

# 422 Unprocessable Entity
HTTP/1.1 422 Unprocessable Entity
Content-Type: application/json

{
  "error": "Unprocessable Entity",
  "message": "Validation failed",
  "errors": {
    "password": "Must be at least 8 characters",
    "email": "Must be a valid email address",
    "age": "Must be between 18 and 120"
  }
}

# 429 Too Many Requests (Rate Limiting)
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640000060

{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Try again in 60 seconds.",
  "retry_after": 60
}

# 451 Unavailable For Legal Reasons
HTTP/1.1 451 Unavailable For Legal Reasons
Link: <https://legal.example.com/reason>; rel="blocked-by"
Content-Type: application/json

{
  "error": "Unavailable For Legal Reasons",
  "message": "This content is not available in your jurisdiction"
}
```
::

### 400 vs 422 Comparison

| Aspect      | 400 Bad Request                     | 422 Unprocessable Entity            |
| ----------- | ----------------------------------- | ----------------------------------- |
| Syntax      | Malformed / unparseable             | Well-formed and parseable           |
| Semantics   | Cannot understand request           | Understood but semantically invalid |
| Example     | Invalid JSON: `{name: "John"`      | Valid JSON but `email: "not-email"` |
| Use case    | Parse errors, missing fields        | Validation errors, business rules   |

### 401 vs 403 Comparison

| Aspect          | 401 Unauthorized                    | 403 Forbidden                        |
| --------------- | ----------------------------------- | ------------------------------------ |
| Authentication  | Not authenticated / invalid token   | Authenticated successfully           |
| Authorization   | N/A (identity unknown)              | Not authorized for this resource     |
| Resolution      | Provide valid credentials           | Request different permissions        |
| WWW-Authenticate| Should include header               | Should NOT include header            |
| Retry with auth | May succeed                         | Will still fail (same credentials)   |

---

### 5xx Server Errors

The server failed to fulfill an apparently valid request.

| Code  | Status                          | Description                                                      |
| ----- | ------------------------------- | ---------------------------------------------------------------- |
| `500` | Internal Server Error           | Generic server error (unhandled exception)                       |
| `501` | Not Implemented                 | Server does not support the functionality required               |
| `502` | Bad Gateway                     | Server acting as gateway received invalid response               |
| `503` | Service Unavailable             | Server temporarily unable to handle request                      |
| `504` | Gateway Timeout                 | Gateway/proxy did not receive timely response                    |
| `505` | HTTP Version Not Supported      | HTTP version in request not supported                            |
| `506` | Variant Also Negotiates         | Internal content negotiation configuration error                 |
| `507` | Insufficient Storage (WebDAV)   | Server unable to store the representation                        |
| `508` | Loop Detected (WebDAV)          | Infinite loop detected while processing                          |
| `510` | Not Extended                    | Further extensions required for request                          |
| `511` | Network Authentication Required | Client must authenticate for network access (captive portal)     |

::code-preview
---
class: "[&>div]:*:my-0"
---
5xx status code examples.

#code
```http
# 500 Internal Server Error
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
  "error": "Internal Server Error",
  "message": "An unexpected error occurred",
  "request_id": "req-abc123",
  "timestamp": "2024-01-01T12:00:00Z"
}

# Common causes:
# - Unhandled exceptions
# - Database connection failures
# - Null pointer errors
# - Configuration errors
# - Dependency failures

# 501 Not Implemented
HTTP/1.1 501 Not Implemented
Content-Type: application/json

{
  "error": "Not Implemented",
  "message": "PATCH method is not implemented for this resource"
}

# 502 Bad Gateway
HTTP/1.1 502 Bad Gateway
Content-Type: application/json

{
  "error": "Bad Gateway",
  "message": "The upstream server returned an invalid response"
}

# Common causes:
# - Backend server crashed
# - Backend returned malformed response
# - DNS resolution failure
# - Connection refused by backend

# 503 Service Unavailable
HTTP/1.1 503 Service Unavailable
Retry-After: 300
Content-Type: application/json

{
  "error": "Service Unavailable",
  "message": "Server is under maintenance. Please try again later.",
  "retry_after": 300,
  "maintenance_window": "2024-01-01T12:00:00Z to 2024-01-01T13:00:00Z"
}

# Common causes:
# - Server overloaded
# - Planned maintenance
# - Dependency service down
# - Rate limiting at server level

# 504 Gateway Timeout
HTTP/1.1 504 Gateway Timeout
Content-Type: application/json

{
  "error": "Gateway Timeout",
  "message": "The upstream server did not respond in time"
}

# Common causes:
# - Backend server too slow
# - Database query timeout
# - Long-running computation
# - Network issues between proxy and backend

# 511 Network Authentication Required (Captive Portal)
HTTP/1.1 511 Network Authentication Required
Content-Type: text/html

<html>
<body>
  <h1>WiFi Login Required</h1>
  <p>Please authenticate to access the internet.</p>
  <form action="/login">...</form>
</body>
</html>
```
::

### 502 vs 503 vs 504 Comparison

| Aspect       | 502 Bad Gateway               | 503 Service Unavailable        | 504 Gateway Timeout            |
| ------------ | ----------------------------- | ------------------------------ | ------------------------------ |
| Issue        | Invalid upstream response     | Server can't handle request    | Upstream response too slow     |
| Upstream     | Responded but invalid         | May or may not be reachable    | Did not respond in time        |
| Temporary    | Usually                       | Usually                        | Usually                        |
| Common cause | Backend crash                 | Overload / maintenance         | Slow query / network issue     |
| Retry        | Yes (after short delay)       | Yes (check Retry-After)        | Yes (after short delay)        |

---

## Complete Status Code Quick Reference

::code-preview
---
class: "[&>div]:*:my-0"
---
All HTTP status codes at a glance.

#code
```
# 1xx - Informational
100 Continue
101 Switching Protocols
102 Processing
103 Early Hints

# 2xx - Success
200 OK
201 Created
202 Accepted
203 Non-Authoritative Information
204 No Content
205 Reset Content
206 Partial Content
207 Multi-Status
208 Already Reported
226 IM Used

# 3xx - Redirection
300 Multiple Choices
301 Moved Permanently
302 Found
303 See Other
304 Not Modified
307 Temporary Redirect
308 Permanent Redirect

# 4xx - Client Errors
400 Bad Request
401 Unauthorized
402 Payment Required
403 Forbidden
404 Not Found
405 Method Not Allowed
406 Not Acceptable
407 Proxy Authentication Required
408 Request Timeout
409 Conflict
410 Gone
411 Length Required
412 Precondition Failed
413 Payload Too Large
414 URI Too Long
415 Unsupported Media Type
416 Range Not Satisfiable
417 Expectation Failed
418 I'm a Teapot
421 Misdirected Request
422 Unprocessable Entity
423 Locked
424 Failed Dependency
425 Too Early
426 Upgrade Required
428 Precondition Required
429 Too Many Requests
431 Request Header Fields Too Large
451 Unavailable For Legal Reasons

# 5xx - Server Errors
500 Internal Server Error
501 Not Implemented
502 Bad Gateway
503 Service Unavailable
504 Gateway Timeout
505 HTTP Version Not Supported
506 Variant Also Negotiates
507 Insufficient Storage
508 Loop Detected
510 Not Extended
511 Network Authentication Required
```
::

---

## API Authentication Methods

### Authentication Comparison

| Method            | Security | Complexity | Stateless | Use Case                           |
| ----------------- | -------- | ---------- | --------- | ---------------------------------- |
| API Key           | Low      | Low        | Yes       | Public APIs, simple access control |
| Basic Auth        | Low      | Low        | Yes       | Internal APIs, simple systems      |
| Bearer Token      | Medium   | Medium     | Yes       | General purpose API auth           |
| JWT               | Medium   | Medium     | Yes       | Microservices, SPA authentication  |
| OAuth 2.0         | High     | High       | Yes       | Third-party access, social login   |
| HMAC              | High     | Medium     | Yes       | API integrity verification         |
| mTLS              | Very High| High       | Yes       | Service-to-service, zero trust     |
| Session Cookie    | Medium   | Low        | No        | Traditional web applications       |

### Authentication Examples

::code-preview
---
class: "[&>div]:*:my-0"
---
API authentication header examples.

#code
```http
# API Key (Header)
GET /api/data HTTP/1.1
X-API-Key: abc123def456ghi789

# API Key (Query Parameter)
GET /api/data?api_key=abc123def456ghi789 HTTP/1.1

# Basic Authentication
GET /api/data HTTP/1.1
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
# Base64 encoded "username:password"

# Bearer Token
GET /api/data HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# OAuth 2.0 Bearer Token
GET /api/data HTTP/1.1
Authorization: Bearer ya29.a0AfH6SMBJ...

# Digest Authentication
GET /api/data HTTP/1.1
Authorization: Digest username="admin", realm="api", nonce="abc123", uri="/api/data", response="hash..."

# HMAC Signature
GET /api/data HTTP/1.1
Authorization: HMAC-SHA256 Credential=access_key/20240101/api, Signature=calculated_hmac_signature
X-Date: 20240101T120000Z

# AWS Signature V4
GET /api/data HTTP/1.1
Authorization: AWS4-HMAC-SHA256 Credential=AKID.../20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=calculated_signature
X-Amz-Date: 20240101T120000Z

# Cookie-based Session
GET /api/data HTTP/1.1
Cookie: session_id=abc123xyz789; csrf_token=def456
```
::

### OAuth 2.0 Flows

::code-preview
---
class: "[&>div]:*:my-0"
---
OAuth 2.0 grant types.

#code
```
# 1. Authorization Code Flow (most secure, server-side apps)
# Step 1: Redirect user to authorization server
GET https://auth.example.com/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://app.com/callback&
  scope=read+write&
  state=random_state_value

# Step 2: User authenticates and approves
# Step 3: Auth server redirects back with code
GET https://app.com/callback?code=AUTH_CODE&state=random_state_value

# Step 4: Exchange code for token
POST https://auth.example.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=https://app.com/callback&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET

# Response
{"access_token": "...", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "..."}

# 2. Authorization Code + PKCE (mobile/SPA apps)
# Generate code_verifier and code_challenge
code_verifier = random_string(43-128 chars)
code_challenge = BASE64URL(SHA256(code_verifier))

# Step 1: Include challenge in auth request
GET https://auth.example.com/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  code_challenge=CHALLENGE&
  code_challenge_method=S256&
  redirect_uri=https://app.com/callback

# Step 4: Include verifier in token request
POST https://auth.example.com/token
grant_type=authorization_code&
code=AUTH_CODE&
code_verifier=VERIFIER&
client_id=CLIENT_ID

# 3. Client Credentials Flow (machine-to-machine)
POST https://auth.example.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET&
scope=read

# 4. Refresh Token Flow
POST https://auth.example.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=REFRESH_TOKEN&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET
```
::

---

## API Rate Limiting

::code-preview
---
class: "[&>div]:*:my-0"
---
Rate limiting headers and responses.

#code
```http
# Rate limit headers in response
HTTP/1.1 200 OK
X-RateLimit-Limit: 1000                    # Max requests per window
X-RateLimit-Remaining: 995                 # Remaining requests
X-RateLimit-Reset: 1640000000              # Window reset timestamp
X-RateLimit-Window: 3600                   # Window duration in seconds

# Rate limited response
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640000060

{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded",
  "retry_after": 60
}

# Common rate limiting strategies
# Fixed Window:     100 requests per 1 hour
# Sliding Window:   100 requests per rolling 1 hour
# Token Bucket:     Tokens refill at fixed rate
# Leaky Bucket:     Requests processed at fixed rate
```
::

### Rate Limit Headers Reference

| Header                     | Description                                |
| -------------------------- | ------------------------------------------ |
| `X-RateLimit-Limit`        | Maximum requests allowed per window        |
| `X-RateLimit-Remaining`    | Remaining requests in current window       |
| `X-RateLimit-Reset`        | Unix timestamp when window resets          |
| `X-RateLimit-Window`       | Duration of rate limit window (seconds)    |
| `Retry-After`              | Seconds to wait before retrying (standard) |
| `RateLimit-Policy`         | Rate limit policy description              |

---

## API Pagination

::code-preview
---
class: "[&>div]:*:my-0"
---
Common API pagination patterns.

#code
```http
# 1. Offset-based pagination
GET /api/users?offset=0&limit=25
GET /api/users?offset=25&limit=25
GET /api/users?offset=50&limit=25

# Response
{
  "data": [...],
  "pagination": {
    "total": 150,
    "offset": 0,
    "limit": 25,
    "has_more": true
  }
}

# 2. Page-based pagination
GET /api/users?page=1&per_page=25
GET /api/users?page=2&per_page=25

# Response
{
  "data": [...],
  "meta": {
    "current_page": 1,
    "per_page": 25,
    "total_pages": 6,
    "total_count": 150
  }
}

# 3. Cursor-based pagination (best for large datasets)
GET /api/users?limit=25
GET /api/users?cursor=eyJpZCI6MjV9&limit=25

# Response
{
  "data": [...],
  "pagination": {
    "next_cursor": "eyJpZCI6NTB9",
    "has_next": true
  }
}

# 4. Link header pagination (GitHub style)
HTTP/1.1 200 OK
Link: <https://api.example.com/users?page=2>; rel="next",
      <https://api.example.com/users?page=6>; rel="last",
      <https://api.example.com/users?page=1>; rel="first"

# 5. HATEOAS pagination
{
  "data": [...],
  "_links": {
    "self":  {"href": "/api/users?page=2"},
    "first": {"href": "/api/users?page=1"},
    "prev":  {"href": "/api/users?page=1"},
    "next":  {"href": "/api/users?page=3"},
    "last":  {"href": "/api/users?page=10"}
  }
}
```
::

### Pagination Comparison

| Method      | Pros                              | Cons                              | Best For                  |
| ----------- | --------------------------------- | --------------------------------- | ------------------------- |
| Offset      | Simple, allows jumping to page    | Slow on large datasets            | Small datasets            |
| Page        | Intuitive for users               | Same issues as offset             | User-facing APIs          |
| Cursor      | Consistent, performant            | No random page access             | Large datasets, feeds     |
| Keyset      | Very performant                   | Complex implementation            | Real-time data, timelines |

---

## API Error Response Best Practices

::code-preview
---
class: "[&>div]:*:my-0"
---
Well-structured API error responses.

#code
```json
// Simple error response
{
  "error": "Not Found",
  "message": "User with ID 999 not found"
}

// Detailed error response
{
  "status": 422,
  "error": "Unprocessable Entity",
  "message": "Validation failed",
  "code": "VALIDATION_ERROR",
  "request_id": "req-550e8400-e29b",
  "timestamp": "2024-01-01T12:00:00Z",
  "errors": [
    {
      "field": "email",
      "code": "INVALID_FORMAT",
      "message": "Must be a valid email address",
      "value": "not-an-email"
    },
    {
      "field": "password",
      "code": "TOO_SHORT",
      "message": "Must be at least 8 characters",
      "min_length": 8
    }
  ],
  "documentation_url": "https://docs.api.com/errors/VALIDATION_ERROR"
}

// RFC 7807 Problem Details (standard)
{
  "type": "https://api.example.com/errors/validation",
  "title": "Validation Error",
  "status": 422,
  "detail": "The request body contains invalid fields",
  "instance": "/api/users",
  "errors": [
    {"pointer": "/email", "detail": "Invalid email format"}
  ]
}
```
::

---

## Testing APIs with cURL

::code-preview
---
class: "[&>div]:*:my-0"
---
Comprehensive cURL examples for API testing.

#code
```bash
# GET request
curl https://api.example.com/users
curl -X GET https://api.example.com/users

# GET with headers
curl -H "Authorization: Bearer <token>" \
     -H "Accept: application/json" \
     https://api.example.com/users

# POST with JSON
curl -X POST https://api.example.com/users \
     -H "Content-Type: application/json" \
     -d '{"name":"John","email":"john@example.com"}'

# POST with form data
curl -X POST https://api.example.com/login \
     -d "username=admin&password=secret"

# POST with file upload
curl -X POST https://api.example.com/upload \
     -F "file=@/path/to/file.pdf" \
     -F "description=My document"

# PUT request
curl -X PUT https://api.example.com/users/123 \
     -H "Content-Type: application/json" \
     -d '{"name":"Updated","email":"new@example.com"}'

# PATCH request
curl -X PATCH https://api.example.com/users/123 \
     -H "Content-Type: application/json" \
     -d '{"email":"patched@example.com"}'

# DELETE request
curl -X DELETE https://api.example.com/users/123 \
     -H "Authorization: Bearer <token>"

# HEAD request (headers only)
curl -I https://api.example.com/users

# OPTIONS request
curl -X OPTIONS https://api.example.com/users -i

# Verbose output (debug)
curl -v https://api.example.com/users

# Include response headers
curl -i https://api.example.com/users

# Follow redirects
curl -L https://api.example.com/old-endpoint

# Set cookies
curl -b "session=abc123" https://api.example.com/profile

# Save cookies
curl -c cookies.txt https://api.example.com/login

# Send cookies from file
curl -b cookies.txt https://api.example.com/profile

# Basic authentication
curl -u username:password https://api.example.com/admin

# Set custom User-Agent
curl -A "MyApp/1.0" https://api.example.com/users

# Set timeout
curl --connect-timeout 5 --max-time 10 https://api.example.com/users

# Output to file
curl -o response.json https://api.example.com/users

# Silent mode
curl -s https://api.example.com/users

# Pretty print JSON (pipe to jq)
curl -s https://api.example.com/users | jq .

# Show only status code
curl -s -o /dev/null -w "%{http_code}" https://api.example.com/users

# Show timing info
curl -s -o /dev/null -w "DNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTLS: %{time_appconnect}s\nTotal: %{time_total}s\n" https://api.example.com

# Proxy through Burp Suite
curl -x http://127.0.0.1:8080 -k https://api.example.com/users

# Ignore SSL certificate errors
curl -k https://self-signed.example.com/api

# Send raw data from file
curl -X POST https://api.example.com/import \
     -H "Content-Type: application/json" \
     -d @data.json

# Multiple requests
curl https://api.example.com/users/1 https://api.example.com/users/2

# HTTP/2
curl --http2 https://api.example.com/users
```
::

---

## Testing APIs with PowerShell

::code-preview
---
class: "[&>div]:*:my-0"
---
API testing using PowerShell.

#code
```powershell
# GET request
Invoke-RestMethod -Uri "https://api.example.com/users" -Method GET

# GET with headers
$headers = @{
    "Authorization" = "Bearer <token>"
    "Accept" = "application/json"
}
Invoke-RestMethod -Uri "https://api.example.com/users" -Headers $headers

# POST with JSON
$body = @{
    name = "John"
    email = "john@example.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://api.example.com/users" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body

# PUT request
Invoke-RestMethod -Uri "https://api.example.com/users/123" `
    -Method PUT `
    -ContentType "application/json" `
    -Body ($body | ConvertTo-Json)

# DELETE request
Invoke-RestMethod -Uri "https://api.example.com/users/123" `
    -Method DELETE `
    -Headers $headers

# Get full response with headers
$response = Invoke-WebRequest -Uri "https://api.example.com/users" -Method GET
$response.StatusCode
$response.Headers
$response.Content | ConvertFrom-Json

# File upload
$form = @{
    file = Get-Item "C:\file.pdf"
}
Invoke-RestMethod -Uri "https://api.example.com/upload" `
    -Method POST `
    -Form $form

# Basic authentication
$cred = Get-Credential
Invoke-RestMethod -Uri "https://api.example.com/admin" `
    -Credential $cred

# Ignore SSL errors
Invoke-RestMethod -Uri "https://self-signed.example.com/api" `
    -SkipCertificateCheck
```
::

---

## API Documentation Standards

| Standard     | Description                                 | File Format  |
| ------------ | ------------------------------------------- | ------------ |
| OpenAPI 3.0  | REST API specification (formerly Swagger)   | YAML / JSON  |
| Swagger 2.0  | Legacy REST API specification               | YAML / JSON  |
| RAML         | RESTful API Modeling Language               | YAML         |
| API Blueprint | High-level API description                 | Markdown     |
| WSDL         | Web Services Description Language (SOAP)    | XML          |
| AsyncAPI     | Event-driven API specification              | YAML / JSON  |
| GraphQL SDL  | GraphQL Schema Definition Language          | SDL          |
| gRPC Proto   | Protocol Buffers definition                 | .proto       |

### OpenAPI Example

::code-preview
---
class: "[&>div]:*:my-0"
---
OpenAPI 3.0 specification example.

#code
```yaml
openapi: 3.0.3
info:
  title: Users API
  version: 1.0.0
  description: API for managing users

servers:
  - url: https://api.example.com/v1

paths:
  /users:
    get:
      summary: List all users
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            default: 1
        - name: limit
          in: query
          schema:
            type: integer
            default: 25
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/User'
        '401':
          description: Unauthorized

    post:
      summary: Create a user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUser'
      responses:
        '201':
          description: User created
        '422':
          description: Validation error

components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
        email:
          type: string
          format: email

    CreateUser:
      type: object
      required:
        - name
        - email
      properties:
        name:
          type: string
        email:
          type: string
          format: email

  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

security:
  - bearerAuth: []
```
::

---

## Common API Endpoints to Test

::code-preview
---
class: "[&>div]:*:my-0"
---
Common API discovery paths.

#code
```
# Documentation
/api
/api/v1
/api/v2
/api/docs
/api/swagger
/api/swagger.json
/api/swagger-ui.html
/api/openapi.json
/api/openapi.yaml
/api-docs
/docs
/redoc
/graphql
/graphiql
/playground

# Authentication
/api/login
/api/auth
/api/auth/login
/api/auth/register
/api/auth/logout
/api/auth/refresh
/api/auth/forgot-password
/api/auth/reset-password
/api/auth/verify
/api/oauth/token
/api/oauth/authorize

# User management
/api/users
/api/users/me
/api/users/profile
/api/users/settings
/api/admin/users

# Health & Status
/api/health
/api/healthcheck
/api/status
/api/info
/api/version
/api/ping
/actuator/health            # Spring Boot
/actuator/env
/actuator/info
/_debug
/debug/vars                 # Go
/server-status              # Apache
/nginx_status               # Nginx

# Common internal
/api/admin
/api/internal
/api/config
/api/metrics
/api/logs
/api/debug
/api/test
```
::

---

## References

- [MDN Web Docs - HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)
- [RFC 7231 - HTTP/1.1 Semantics](https://www.rfc-editor.org/rfc/rfc7231)
- [RFC 7235 - HTTP Authentication](https://www.rfc-editor.org/rfc/rfc7235)
- [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7519 - JWT](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7807 - Problem Details](https://www.rfc-editor.org/rfc/rfc7807)
- [OpenAPI Specification](https://spec.openapis.org/oas/v3.0.3)
- [HTTP/2 Specification (RFC 7540)](https://www.rfc-editor.org/rfc/rfc7540)
- [HTTP/3 Specification (RFC 9114)](https://www.rfc-editor.org/rfc/rfc9114)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [REST API Tutorial](https://restfulapi.net/)
- [GraphQL Specification](https://spec.graphql.org/)
- [gRPC Documentation](https://grpc.io/docs/)
- [Postman Learning Center](https://learning.postman.com/)
- [HTTPie Documentation](https://httpie.io/docs)

::tip
Understanding **HTTP fundamentals** and **API architecture** is essential for both building secure applications and testing them. Every web vulnerability — from SQL injection to SSRF — exploits how HTTP requests and responses are handled. Master the protocol, and you master the attack surface.
::
:::