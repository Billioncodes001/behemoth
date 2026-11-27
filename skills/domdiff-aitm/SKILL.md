---
name: domdiff-aitm
description: DOMDIFFER-style AiTM phishing operations (DOM mirroring, reverse-proxy relay, scanner evasion). For authorized phishing simulation and red-team engagements only.
---

# AiTM Phishing — DOMDIFFER Techniques (Security Testing Only)

## Legal Warning
**ONLY deploy phish sites for domains/accounts you are authorized to test.**

## Background
DOMDIFFER (Push Security, 2026) is an adversary-in-the-middle (AiTM) kit that topped
breakthrough-rate rankings for months by relaying *live* sign-in pages (DOM mirroring)
instead of static replicas, and by giving security scanners the genuine page while
humans get the kit. BEHEMOTH implements the same technique family generically via the
`manage_phish_site` / `phish_captures` tools — for ANY login target, not just
Google/Microsoft.

## Modes (choose per target)
- **`mode=proxy`** — reverse-proxy relay: the genuine page is rewritten on the fly into
  the phish host; a beacon captures form fields and forwards the real login untouched.
  Works everywhere, low fidelity against adaptive multi-step logins.
- **`mode=mirror`** — DOM mirroring: an attacker-side headless Chrome opens the real
  login page; the victim's shell page renders its LIVE DOM and every keystroke/click is
  replayed into that browser. The real site drives the whole flow (adaptive auth,
  MFA steps), and the session cookies are harvested after login. Requires Chrome on the
  BEHEMOTH host; one browser per victim (heavier, highest fidelity).

## Scanner Evasion (the DOMDIFFER trick)
- Always set `bot_action=passthrough` for realistic campaigns: security scanners
  (headless UAs, crawler UAs, scanner IPs/CIDRs) receive the *genuine upstream page
  byte-for-byte* and never see the kit.
- Use `block` to 404 scanners or `decoy` + `decoy_html` to serve a benign page when
  passthrough would leak the campaign.
- Override `bot_ua` with target-specific scanner fingerprints when known.

## Operational Checklist
1. `manage_phish_site(action=create, target_url=..., hosts=..., mode=..., bot_action=passthrough)`
2. Point the phish hostname's DNS (or the target's `/etc/hosts` in a lab) at the
   BEHEMOTH phish listener (`BEHEMOTH_PHISH_ADDR`, default `127.0.0.1:8789`); enable TLS
   via `BEHEMOTH_PHISH_TLS_CERT/KEY` for https lures.
3. For multi-domain targets (e.g. Google), register `extra_target_hosts` (e.g.
   `www.google.com`) so cross-host asset references are rewritten too.
4. Deliver the lure (fake calendar invite / voicemail notification patterns worked for
   DOMDIFFER because trusted notification channels slip past email filters).
5. Poll `phish_captures` for credentials + session cookies; cookies replay directly in
   a browser to inherit the authenticated session (AiTM bypasses MFA by design).
6. Record verified entries via `record_intelligence` and tear the site down
   (`action=disable` then `delete`) after the engagement window.

## OPSEC Rules
- Rotate phish hostnames between campaigns; never reuse a burned domain.
- Keep `bot_action=passthrough` ON whenever URL-scanning email gateways are in play.
- Mirror mode spins a real browser against the target: keep victim volume low and
  respect the target's auth rate limits.
- Never modify the captured page content beyond the host swap in proxy mode — injected
  scripts are a fingerprint (mirror mode injects nothing into what the victim's origin
  serves; the victim only ever talks to the shell page).
