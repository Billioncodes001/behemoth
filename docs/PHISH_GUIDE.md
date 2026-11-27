# AiTM Phishing Guide (DOMDIFFER-style)

BEHEMOTH ships a self-contained adversary-in-the-middle phishing capability modeled on
the DOMDIFFER kit family publicized by Push Security in 2026 (the code is original —
see `THIRD_PARTY.md`). It targets **any** HTTP login page, not only Google/Microsoft.

## What DOMDIFFER does, and what we implemented

| DOMDIFFER feature | BEHEMOTH implementation |
|---|---|
| Reverse-proxy AiTM relay | `mode=proxy` — `httputil.ReverseProxy` with URL/`Location`/`Set-Cookie` rewriting and a credential-capture beacon (`/__bhm/collect`) that lets the genuine login proceed untouched |
| DOM mirroring (relay the live sign-in DOM from an attacker-side browser) | `mode=mirror` — a per-victim headless Chrome (chromedp) drives the real page; a WebSocket streams DOM snapshots to the victim's shell page and replays victim input/clicks into that browser; session cookies are harvested when the page navigates past the entry URL |
| Scanner evasion (scanners get the genuine page) | `bot_action=passthrough` — scanners (UA/regex + IP/CIDR matchers) receive the upstream page byte-for-byte; `block` and `decoy` actions are also available |
| Rapid domain rotation | multiple `hosts` entries per site and per-campaign sites; rotation tooling is future work |
| Credential + session capture | `phish` captures store (fields + session cookies) under `<dataDir>/phish/captures.jsonl`, readable via the `phish_captures` tool |

## Agent tools

| Tool | Access | Summary |
|---|---|---|
| `manage_phish_site` | write | `create` / `update` / `list` / `enable` / `disable` / `delete` phish sites (target, mode, hosts, capture, bot filters, decoy page). |
| `phish_captures` | read | Read harvested credentials and session cookies (optionally filtered by `site_id`). |

## Listener & configuration

- `BEHEMOTH_PHISH_ADDR` — dedicated listener address (default `127.0.0.1:8789`); the
  listener starts lazily when the first site is enabled.
- `BEHEMOTH_PHISH_PUBLIC_URL` — base URL advertised to operators.
- `BEHEMOTH_PHISH_TLS_CERT` / `BEHEMOTH_PHISH_TLS_KEY` — optional TLS for the listener.
- State lives under `<dataDir>/phish/` (`sites.json`, `captures.jsonl`) and survives
  restarts, mirroring the C2 store layout.

Sites are multiplexed on the one listener by `Host` header: register the phish
hostnames you control (`hosts`) and point their DNS at the server.

## Mirror mode requirements & limits

- Requires a local Chrome/Chromium binary (chromedp launches it); one attacker-side
  browser per victim session (capped at 15 minutes total, 3 minutes idle).
- Input/click relay uses CSS paths computed in the victim's shell; heavily
  re-rendering SPAs may occasionally need a fresh snapshot — acceptable for login
  flows, which are DOMDIFFER's target use case too.
- The victim's browser never contacts the real origin; it renders relayed snapshots,
  which is what makes the flow indistinguishable from the genuine page to the user.

## Evasion notes

- `bot_action=passthrough` is the default recommendation: URL scanners and sandbox
  fetchers index the genuine page, so reputation systems see real content.
- Keep campaigns short, rotate hostnames, and prefer trusted-notification lures
  (calendar invites / voicemail notifications) as documented in the
  `skills/domdiff-aitm/SKILL.md` skill.
