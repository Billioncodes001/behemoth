---
name: captcha-solving
description: Defeat CAPTCHAs during authenticated testing — classic image captchas via the built-in solve_captcha OCR loop, and modern invisible widgets (reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile) via the token service — without burning LLM tokens.
---

# CAPTCHA Solving Playbook

Use this skill whenever a login, signup, or comment form is protected by a CAPTCHA (HTTP form still re-renders with "Invalid CAPTCHA"-style errors, or the page embeds a reCAPTCHA/hCaptcha/Turnstile widget). **Never** fetch the captcha image and read it yourself in a loop — that burns millions of tokens for near-zero progress.

## 1. Classic image captchas (django-simple-captcha, PHP GD, etc.)

Call `solve_captcha` with `mode: "form"` (default) and the form details you already know:

```json
{
  "page_url": "https://portal.example.com/graduate/signup",
  "extra_fields": {"username": "probe1", "email": "probe1@example.com", "password": "Xy123456!"},
  "success_contains": ["registration complete"],
  "max_attempts": 60,
  "delay_seconds": 2
}
```

What the tool does internally, in ONE call:
1. Fetches the page fresh every round (cookie jar + CSRF/hidden fields preserved — `captcha_0` hash fields are posted automatically).
2. Discovers the captcha `<img src="...captcha...">` and the answer field (`captcha_1` by convention, auto-detected).
3. Runs OCR with multiple preprocessing variants (grayscale → Otsu threshold → despeckle → 3-4x upscale → invert) across several tesseract segmentation modes, voting on candidates.
4. Submits, judges success/failure by markers (defaults cover "Invalid CAPTCHA" / 验证码错误 / ...), and retries with a **fresh challenge**.

Guidelines:
- Set `max_attempts` high (40-100) and `delay_seconds` 1-3 — each round costs zero tokens; expect single-attempt OCR accuracy of only a few percent on noisy captchas (Django simple-captcha images are ~82px with per-glyph rotation), which still guarantees a solve within minutes.
- Judgment markers: `failure_contains` for unusual captcha-error phrasings (e.g. a site that just re-renders with a Django `errorlist`); `reject_contains` for PERMANENT non-captcha rejections like "email already registered" — those stop the loop after one attempt (sensible defaults already stop on "already registered/exists/taken"-style text; pass `["-"]` to disable). Without this the loop would burn every attempt on an error no captcha answer can fix.
- If the form requires specific field values (username/email/password), always pass them in `extra_fields`; if those fields have their own validation errors, the response will never contain your success marker — read the returned `attempts[].detail` to spot non-captcha rejections.
- If the site answers with a redirect (`302`) and no captcha form anymore, the tool counts it as solved.
- The form loop runs in its OWN session — the cookies are not returned. When you need the session created by the submit (e.g. a signup that auto-logs you in), use `mode: "ocr"` instead: fetch the page yourself, get ranked candidates for the captcha image, and submit with your own requests/browser session so you keep the authenticated cookies. Use `mode: "form"` when you only need the action to succeed.
- After solving, capture the session (cookies) your own flow needs — e.g. repeat the same POST with the returned answer and your own requests session, or continue in the same browser session.

## 2. Modern invisible captchas (reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile)

Call `solve_captcha` with `mode: "token"`:

```json
{
  "mode": "token",
  "captcha_type": "turnstile",
  "site_key": "0x4AAAAAAA...",
  "page_url": "https://target.example.com/login"
}
```

- Requires `captcha_api_key` (2Captcha-compatible service) — set it in `.env` (`CAPTCHA_API_KEY`) or platform settings.
- The result carries `token` + ready-to-run `inject_js`: evaluate it in the page (browser_inspect / Playwright) so the `g-recaptcha-response` / `h-captcha-response` / `cf-turnstile-response` field is filled and the widget callback fires, then submit the form normally.
- Cloudflare "Just a moment..." interstitials are usually cleared by the headless browser itself; if you keep seeing the challenge, rotate the proxy (`manage_proxy_pool`) — residential exits pass far more often than datacenter IPs.

## 3. Choosing the mode

- Visible distorted-text image with a text input → `mode: "form"`.
- Widget with `sitekey=`, `data-sitekey=`, `render=`, `.hcaptcha.com`, `challenges.cloudflare.com` → `mode: "token"`.
- You already have the PNG bytes (e.g. from curl) and just want candidate readings → `mode: "ocr"` with `image_base64`.
