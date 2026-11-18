---
name: redteam-detection-surface-and-resilience
description: SOC-evasive operations framework. Teaches agents to operate below SIEM/SOC detection thresholds using rate limiting, account tiering, timing jitter, and behavioral camouflage.
---

# Red Team Detection Surface & Resilience

## Core Principle
**Invisible operations win wars.** Every action generates logs. Make them look normal.

## MANDATORY Rate Limiting Rules

### Request Spacing (NEVER violate)
| Operation | Min Interval | Max/Window |
|-----------|-------------|------------|
| Same target domain/IP | 180s | 10 per 30min |
| Auth attempts | 300s | 3 per 15min |
| File/directory access | 60s | 20 per 30min |
| Database queries | 120s | 15 per 30min |

### Concurrency Limits
- Max **2 simultaneous connections** to any single target
- Queue additional requests; never parallelize against same target

### Timing Jitter
- Add **random 15-45 second delay** between EVERY operation
- Use `sleep $((RANDOM % 30 + 15))` in bash
- Never use fixed intervals

### Failure Backoff
- 4xx/5xx error: wait **300s** before retry
- Timeout: wait **600s** before retry

## Account & Access Tiering (MANDATORY)

### When Reading Data
```
WRONG: Connect as admin/domain-admin/root
CORRECT: Use read-only service account or low-priv user
```

### Account Priority
1. Read-only monitoring accounts (for recon)
2. Service/application accounts (for API access)
3. Compromised low-priv accounts (for lateral movement)
4. Admin accounts (ONLY when absolutely necessary)

### Behavioral Camouflage
- Match activity to **target's timezone**
- Avoid **off-hours** (22:00-06:00 target local time)
- Mix legitimate requests with actual operations (**3:1 ratio**)
- If off-hours needed, make it look like **automated backup/cron**

## Detection Surface Reduction

### TLS & HTTP
- Match JA3/JA4 fingerprints to common browsers
- Use `--tlsv1.2` or `--tlsv1.3` only
- Rotate User-Agent from pool of 20+ real browser strings
- Match header order: Accept, Accept-Language, Accept-Encoding, Connection, User-Agent

### DNS Patterns
- NEVER sequential subdomain enumeration
- ALWAYS shuffle/subsample target lists first
- Use DNS resolver rotation if available

## SIEM Triggers to AVOID

| Pattern | Why It Triggers | Alternative |
|---------|-----------------|-------------|
| Multiple auth failures same IP | Brute force detection | Space 5+ min apart |
| Unusual file access | EDR monitoring | Mix with legit paths |
| Large data transfer | DLP/exfil detection | Chunk <100KB over hours |
| Off-hours admin activity | UEBA anomaly | Match timezone |
| Unusual process execution | EDR process monitor | LOLBAS only |
| Port scan single IP | Network IDS/IPS | Slow, randomize order |

## Data Exfiltration Guidelines

### Limits
- Single event: **< 100KB**
- Daily total per target: **< 500KB**
- Spread over **minimum 4 hours**

### Methods (ordered by stealth)
1. DNS tunneling (rarely monitored)
2. HTTPS POST to benign endpoint
3. Cookie-based exfiltration
4. CSS background-image exfil
5. WebSocket to CDN-looking domain

## Validation Checklist

- [ ] Lowest-privilege account for this task?
- [ ] Request interval >= 180s for this target?
- [ ] Added 15-45s random jitter?
- [ ] Realistic User-Agent?
- [ ] Within 10-request/30min limit?
- [ ] Appropriate for target timezone?
- [ ] 300s+ backoff plan if fails?
- [ ] Normal in SOC dashboard?

*Goal: Complete without anyone knowing you were there.*

