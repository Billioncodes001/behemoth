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
