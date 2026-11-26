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

## 3. Pacing Credential Attacks Through Proxies

Shared/rotating commercial proxy providers (Webshare, Bright Data, IPRoyal, scraped proxies) meter login/sign-up traffic aggressively and flag accounts that hammer it — a "large number of login attempts with different credentials" is *strictly forbidden* on Webshare and repeated waves can require manual verification or get the pool suspended.

- Budget: **≤ ~20 auth-page loads and ≤ 5 credential attempts per target domain per hour** through provider proxies, **≥ 10 s** between auth-page requests. Track the count explicitly (e.g. a local counter file / task fact) instead of eyeballing it.
- Route credential attacks **directly** (disable the proxy for that phase) or through operator-owned dedicated/self-hosted/script-managed proxy exits — provider meters don't apply there. Keep unauthenticated recon on the proxy.
- On `403` / `429` / CAPTCHA wall / `client_connect_auth_revoked`: stop the auth phase, cool down **≥ 30–60 min** (short waits via `Bash sleep`), and persist what was attempted, how many tries were spent, and a resume plan via `record_fact`. Resume on a later run or operator schedule — never tighten the retry loop.
- Default attempt sets, cheapest first: single admin/admin guess → small high-value list (5–10) → pure wordlist brute force only if the endpoint shows no lockout and the budget allows.
- Never mass sign-up through rotating residential proxies (account creation may trigger ID verification and burns pool reputation).
