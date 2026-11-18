---
name: cc-skimmer
description: Credit card skimmer payload generator for e-commerce security testing. Generates JavaScript that captures payment form data for authorized penetration tests.
---

# Credit Card Skimmer (Security Testing Only)

## Legal Warning
**ONLY use on systems you own or have explicit written authorization to test.**

## Payload Types

### Type 1: Form Input Monitor
Monitors form fields for credit card patterns:
- Card number: 13-19 digits, spaces/dashes allowed
- Expiry: MM/YY or MM/YYYY format
- CVV: 3-4 digits

### Type 2: Submit Interceptor
Captures data before form submission:
```javascript
// Key features:
// - Adds event listener before other scripts
// - Captures complete form data
// - Allows original submission to proceed
// - Stores captured data for exfiltration
```

### Type 3: Keylogger Variant
Captures keystrokes in sensitive fields:
- Works even with virtual keyboards
- Records timing patterns
- Detects field focus changes

## Exfiltration Methods (ordered by stealth)

1. **Image Pixel Request** - Data encoded in URL params
2. **CSS Background** - `background-image: url(data:...)`
3. **WebSocket** - Real-time, bypasses most WAFs
4. **DNS Tunneling** - Slow but rarely monitored
5. **Cookie Storage** - Read by first-party script later

## Target Platforms
- Magento 1.x / 2.x
- Shopify (via app injection)
- WooCommerce / WordPress
- Custom cart implementations
- Stripe/PayPal integrations

## Detection Evasion
- Dynamic variable names (generated per deployment)
- Code minification + obfuscation
- Delayed activation (2-5s after page load)
- Graceful failure (no console errors)
- Anti-debugging checks
