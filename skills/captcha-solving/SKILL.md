---
name: captcha-solving
description: Defeat CAPTCHAs during authenticated testing — Image CAPTCHAs (via 2Captcha ImageToTextTask + local Tesseract OCR), Cloudflare Turnstile & Challenge interstitials, reCAPTCHA v2 (standard, invisible, Enterprise), reCAPTCHA v3, and hCaptcha — without burning LLM tokens.
---

# CAPTCHA Solving Playbook (2Captcha + Local OCR)

Use this skill whenever a login, signup, password reset, or API endpoint is protected by a CAPTCHA. **Never** read distorted CAPTCHA images manually with LLM vision in a loop — call `solve_captcha` instead.

BEHEMOTH automatically loads the configured **2Captcha API key** from **System → Settings → Network and tools** into both `solve_captcha` AND live shell environment variables (`$TWO_CAPTCHA_API_KEY` / `$CAPTCHA_API_KEY`, `$CAPTCHA_BASE_URL`).

## 1. Image CAPTCHAs (`mode: "image"` or `mode: "form"`)

### A. Solve a Single Image CAPTCHA via 2Captcha (`mode: "image"`)
When you need to preserve your own browser/session cookies (e.g. Playwright / `requests.Session`):
```json
{
  "mode": "image",
  "image_path": "captcha.png",
  "case_sensitive": true,
  "math": false
}
```
(Accepts `image_path`, `image_url`, or `image_base64`; set `"math": true` for arithmetic images like `7 + 4 = ?`, or `"numeric": 1` for digits-only.)

### B. Automated Form Fetch → Solve → Submit Loop (`mode: "form"`)
When you want one call to handle fresh challenge fetching, CSRF/hidden inputs, solving (fast local OCR on rounds 1–2, escalating automatically to **2Captcha `ImageToTextTask`** when a 2Captcha key is configured), and form submission:
```json
{
  "mode": "form",
  "page_url": "https://portal.example.com/graduate/signup",
  "extra_fields": {"username": "probe1", "email": "probe1@example.com", "password": "Xy123456!"},
  "success_contains": ["registration complete"],
  "use_2captcha": true,
  "max_attempts": 15,
  "delay_seconds": 1
}
```

## 2. Cloudflare Turnstile (Widget & Challenge Interstitials)

```json
{
  "mode": "token",
  "captcha_type": "turnstile",
  "site_key": "0x4AAAAAAA...",
  "page_url": "https://target.example.com/login"
}
```
- **Cloudflare Managed Challenge Interstitials**: Extract `sitekey`, `action`, `cData`, and `chlPageData` from `turnstile.render(...)` / `window._cf_chl_opt` and pass `"action"`, `"cdata"`, `"chl_page_data"`, and `"user_agent"`.
- Evaluate the returned `inject_js` inside Playwright / `browser_inspect` (sets `cf-turnstile-response` and invokes `window.tsCallback` / `data-callback`), using the returned `user_agent` if present.

## 3. Google reCAPTCHA v2 (Checkbox, Invisible & Enterprise)

```json
{
  "mode": "token",
  "captcha_type": "recaptcha_v2",
  "site_key": "6Lc...",
  "page_url": "https://target.example.com/login",
  "invisible": false,
  "enterprise": false
}
```
- Set `"invisible": true` for invisible v2 badges, `"enterprise": true` for `/recaptcha/enterprise.js`, and `"data_s"` if the page sets `data-s`.

## 4. Google reCAPTCHA v3 (Score-Based)

```json
{
  "mode": "token",
  "captcha_type": "recaptcha_v3",
  "site_key": "6Lc...",
  "page_url": "https://target.example.com/api/login",
  "action": "login",
  "min_score": "0.7",
  "enterprise": false
}
```
- Inspect the page's `grecaptcha.execute(siteKey, {action: '...'})` call to pass the exact `"action"` name!

## 5. hCaptcha

```json
{
  "mode": "token",
  "captcha_type": "hcaptcha",
  "site_key": "10000000-ffff-ffff-ffff-000000000001",
  "page_url": "https://target.example.com/register"
}
```

