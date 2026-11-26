---
name: auth-and-jwt-attacks
description: Specialized methodology for testing authentication flows, JWT security (alg:none, weak HMAC secrets, kid injection, key confusion), OAuth/OIDC flaws, session management, password reset poisoning, and MFA bypass.
---

# Authentication & JWT Attack Playbook

Use this skill whenever an application uses JWTs, session cookies, OAuth2/OIDC, SSO, API keys, or multi-step login/reset workflows.

## 1. JWT Inspection & Exploitation
1. **Decode & Inspect**: Base64-decode the JWT header and payload. Record `alg`, `kid`, `jku`, `x5u`, `iss`, `sub`, `role`/`admin` claims, and `exp`.
2. **Algorithm None (`alg: "none"`)**: Strip the signature (keep trailing dot `header.payload.`) and test `none`, `None`, `NONE`.
3. **Weak HMAC Secret Cracking**: For `HS256`/`HS384`/`HS512`, test common secrets (`secret`, `password`, `123456`, `jwt_secret`, application name, environment defaults) using Python (` hmac / PyJWT `) or `hashcat`/`john`.
4. **Header Parameter Injection (`kid`, `jku`, `x5u`)**:
   - Test path traversal in `kid` (`../../../../dev/null` signed with an empty string `""`).
   - Test SQL injection or command injection in `kid`.
5. **Claim Manipulation**: Modify `sub`, `user_id`, `email`, or `role: "admin"` and verify whether the backend validates the signature or only decodes the payload (`jwt.decode(..., options={"verify_signature": False})`).

## 2. Login, Password Reset & MFA Bypass
1. **Authentication Bypass**: Test SQLi/NoSQLi (`{"$ne": null}`, `{"$gt": ""}`) in login JSON/form fields, response manipulation, and forced browsing to authenticated endpoints.
2. **Password Reset Poisoning**: Test `Host` header injection (`Host: attacker.tld`, `X-Forwarded-Host: attacker.tld`) on password reset requests, predictable reset tokens, and token reuse.
3. **OAuth / SSO Flaws**: Test `redirect_uri` validation bypass, missing `state` parameter (CSRF), and token leakage via Referer.

## 3. Pacing Credential Attacks Through Proxies & Cooldown Cron Scheduling

Shared/rotating commercial proxy providers (Webshare, Bright Data, IPRoyal) meter login/sign-up/auth-service traffic aggressively and flag accounts that hammer it — a "large number of login attempts with different credentials" is *strictly forbidden* on Webshare and repeated waves can require manual KYC verification or get the pool suspended.

- **Commercial Provider Proxies (`metered_commercial_proxy: true`)**: Keep **≤ ~20 auth-page loads and ≤ 5 credential attempts per target domain per hour**, **≥ 10 s** between auth-page requests, and NEVER brute-force FTP/SSH/SMTP ports (`21`/`22`/`25`). Track the count explicitly (e.g. a local counter file / task fact) instead of eyeballing it.
- **Scraped Disposable Proxies (`scraped-*`) & Tor**: Unauthenticated `scraped-*` proxies harvested via `scrape_online_proxies` and free Tor circuits (`tor-*`) have **no commercial provider account meter** — switch to `scraped-*` proxies or operator-owned dedicated/self-hosted/script-managed proxy exits whenever higher-volume auth testing is required. **NEVER** disable proxies to connect directly from the BEHEMOTH server IP (direct egress is blocked by platform policy).
- **Automatic Cooldown & Cron Continuation (`schedule_cooldown_resume`)**: Whenever you hit the 5-attempt batch limit or encounter `403` / `429` / CAPTCHA wall / `407` (`client_connect_auth_revoked`), stop the auth phase immediately, cool down **≥ 30–60 min**, persist what was attempted (`record_fact`), and call **`schedule_cooldown_resume(cooldown_minutes=35, repeat_interval_minutes=45, max_runs=4, domain=..., resume_prompt=...)`** so BEHEMOTH automatically resumes the next wave once the system has cooled down — never tighten the retry loop.
- Default attempt sets, cheapest first: single admin/admin guess → small high-value list (≤5 per wave) → multi-wave scheduled continuation via `schedule_cooldown_resume`.
- Never mass sign-up through rotating commercial/residential proxies (account creation may trigger ID verification and burns pool reputation).
