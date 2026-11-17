---
name: waf-and-filter-bypass
description: Techniques for bypassing Web Application Firewalls (WAF), input validation filters, and rate limiters using encoding mutations, HTTP protocol quirks, content-type switching, and payload obfuscation.
---

# WAF & Input Filter Bypass Playbook

Use this skill when a promising vulnerability route is blocked by a WAF (HTTP 403/406/429/501) or application-level sanitization filter.

## 1. HTTP Protocol & Content-Type Evasion
1. **Content-Type Switching**: If `application/x-www-form-urlencoded` is filtered, replay the request as `application/json`, `multipart/form-data`, or `application/xml`.
2. **HTTP Parameter Pollution (HPP)**: Supply duplicate parameters (`?id=1&id=1' UNION SELECT...`) or array/object notation (`?id[]=1'`).
3. **Method Override**: Test `X-HTTP-Method-Override`, `X-Method-Override`, or `_method` query/body parameters.
4. **Origin / IP Trust Headers**: Test `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `X-Originating-IP: 127.0.0.1`, `X-Rewrite-URL`, and `X-Original-URL`.

## 2. Encoding & Payload Obfuscation
- **SQLi**: Replace spaces with comments (`/**/`, `%09`, `%0a`, `+`), use case variation (`uNiOn sElEcT`), hex/char encoding, or scientific notation (`1e0UNION`).
- **XSS / SSTI**: Use HTML entity encoding, Unicode escapes (`\u003c`), JavaScript `String.fromCharCode`, or template attribute access (`request['__class__']`).
- **Command Injection**: Bypass space filters using `${IFS}`, `{cat,/etc/passwd}`, quotes (`c'a't /e't'c/p'a's's'w'd`), or base64 decoding (`echo ... | base64 -d | sh`).
- **Path Traversal**: Test double URL encoding (`%252e%252e%252f`), nested sequences (`....//....//`), and null-byte/semicolon path parameters (`..;/`).
