---
name: data-exfiltration
description: Stealthy data extraction techniques for red team operations. Covers chunking, encoding, timing, and channel selection.
---

# Data Exfiltration

## Pre-Exfil Checklist
- [ ] Data value justifies risk?
- [ ] Exfil channel available and tested?
- [ ] Size within limits (<100KB/event)?
- [ ] Timing plan established?
- [ ] Cleanup procedure ready?

## Exfil Channels (by stealth level)

### Level 1: High Stealth
| Channel | Speed | Detection Risk |
|---------|-------|----------------|
| DNS Tunneling | Very Slow | Very Low |
| ICMP Encapsulation | Slow | Low |
| HTTP Cookie Headers | Medium | Low |
| CSS Exfil | Slow | Low |

### Level 2: Medium Stealth
| Channel | Speed | Detection Risk |
|---------|-------|----------------|
| HTTPS POST (mimic GA) | Fast | Medium |
| WebSocket (CDN domain) | Fast | Medium |
| Webhook to benign service | Fast | Medium |

### Level 3: Lower Stealth (use sparingly)
| Channel | Speed | Detection Risk |
|---------|-------|----------------|
| Direct Upload | Very Fast | High |
| Email Attachment | Fast | High |
| Cloud Storage API | Fast | High |

## Data Preparation

### Chunking Strategy
```python
def chunk_data(data, max_size=100000):  # 100KB chunks
    return [data[i:i+max_size] for i in range(0, len(data), max_size)]
```

### Encoding Options
- **Base64**: Universal, increases size 33%
- **Hex**: No size change, looks like hex strings
- **Zlib+Base64**: Good compression for text
- **Custom XOR**: Avoids pattern matching

## Timing Rules
- Minimum **5 minutes** between chunks
- Random interval: **5-20 minutes**
- Spread large exfil over **4+ hours**
- Avoid predictable patterns
