package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/server/captcha"
	actool "github.com/Autumn-27/norma/tool"
)

// CAPTCHA solving agent tools. A single solve_captcha call performs the whole
// fetch→OCR→submit→judge→retry loop locally (zero LLM tokens), which is what
// keeps agents from hand-reading ASCII art for millions of tokens.

// captchaTools returns the captcha agent tools.
func (s *Server) captchaTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolSolveCaptcha()}
}

// captchaAPIKey resolves the solving-service key: env first, then settings.
func (s *Server) captchaAPIKey() string {
	for _, env := range []string{"CAPTCHA_API_KEY", "TWO_CAPTCHA_API_KEY"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	if s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting("captcha_api_key"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// captchaBaseURL resolves the service base URL (2Captcha-compatible).
func (s *Server) captchaBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("CAPTCHA_BASE_URL")); v != "" {
		return v
	}
	if s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting("captcha_base_url"); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return "https://2captcha.com"
}

// toolSolveCaptcha exposes solve_captcha to agents.
func (s *Server) toolSolveCaptcha() actool.CoreTool {
	return roTool("solve_captcha",
		"Solve CAPTCHAs without burning tokens: mode=form runs the complete local loop (fetch page → discover captcha image + CSRF/hidden fields → OCR with multiple preprocessing variants via tesseract → submit → detect success/failure → retry with a fresh challenge, up to max_attempts) and returns the accepted answer with evidence; mode=ocr returns ranked OCR candidates for one captcha image (image_url or image_base64); mode=token solves modern invisible widgets (recaptcha_v2, recaptcha_v3, hcaptcha, turnstile) via the configured 2Captcha-compatible service and returns the token plus browser injection JS. ALWAYS use this tool instead of manually reading captcha images in a loop.",
		objSchema(map[string]any{
			"mode": map[string]any{
				"type":        "string",
				"enum":        []string{"form", "ocr", "token"},
				"description": "form = full auto-solve loop (default); ocr = read one image and return candidates; token = solve an invisible/reCAPTCHA/hCaptcha/Turnstile widget via the solving service",
			},
			"page_url":           strParam("form mode: URL of the page containing the captcha form (re-fetched for a fresh challenge every attempt)"),
			"form_action":        strParam("form mode: optional explicit form action (auto-discovered from the HTML when omitted)"),
			"method":             strParam("form mode: optional explicit form method (POST by default)"),
			"captcha_image_url":  strParam("form/ocr mode: explicit captcha image URL (auto-discovered from <img src=...captcha...> when omitted)"),
			"captcha_field":      strParam("form mode: answer input name (e.g. captcha_1; auto-discovered when omitted)"),
			"captcha_hash_field": strParam("form mode: hidden challenge-key input name (e.g. captcha_0)"),
			"extra_fields":       map[string]any{"type": "object", "description": "form mode: additional form fields to submit, e.g. {\"username\":\"admin\",\"password\":\"x\"} (hidden/CSRF fields are posted automatically)"},
			"success_contains":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "form mode: case-insensitive body substrings that mean the captcha was accepted"},
			"failure_contains":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "form mode: case-insensitive body substrings that mean the answer was rejected (defaults cover 'Invalid CAPTCHA' style messages)"},
			"reject_contains":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "form mode: NON-captcha rejections like 'email already registered' that must stop the loop instead of retrying (sensible defaults apply; pass [\"-\"] to disable)"},
			"max_attempts":       map[string]any{"type": "integer", "description": "form mode: max fetch→OCR→submit rounds (default 25, max 200). Keep high — each round costs no tokens."},
			"delay_seconds":      map[string]any{"type": "number", "description": "form mode: pause between attempts (default 1s) to avoid rate limits"},
			"timeout_seconds":    map[string]any{"type": "integer", "description": "overall run timeout (default 300s, max 900s)"},
			"proxy":              strParam("optional proxy URL (http://user:pass@host:port) for all requests"),
			"image_url":          strParam("ocr mode: URL of the captcha image to read"),
			"image_base64":       strParam("ocr mode: base64 (or data:) encoded captcha image"),
			"char_whitelist":     strParam("ocr mode: restrict OCR to these characters (default letters+digits)"),
			"captcha_type":       map[string]any{"type": "string", "enum": []string{"recaptcha_v2", "recaptcha_v3", "hcaptcha", "turnstile"}, "description": "token mode: widget type"},
			"site_key":           strParam("token mode: widget sitekey (data-sitekey / sitekey render parameter)"),
			"action":             strParam("token mode (recaptcha_v3): action name"),
			"min_score":          strParam("token mode (recaptcha_v3): minimum score threshold"),
		}),
		solveCaptchaRun(s))
}

// solveCaptchaRun implements the solve_captcha execution.
func solveCaptchaRun(s *Server) func(context.Context, json.RawMessage) (actool.Result, error) {
	return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Mode             string            `json:"mode"`
			PageURL          string            `json:"page_url"`
			FormAction       string            `json:"form_action"`
			Method           string            `json:"method"`
			CaptchaImageURL  string            `json:"captcha_image_url"`
			CaptchaField     string            `json:"captcha_field"`
			CaptchaHashField string            `json:"captcha_hash_field"`
			ExtraFields      map[string]string `json:"extra_fields"`
			SuccessMarkers   []string          `json:"success_contains"`
			FailureMarkers   []string          `json:"failure_contains"`
			RejectMarkers    []string          `json:"reject_contains"`
			MaxAttempts      int               `json:"max_attempts"`
			DelaySeconds     float64           `json:"delay_seconds"`
			TimeoutSeconds   int               `json:"timeout_seconds"`
			Proxy            string            `json:"proxy"`
			ImageURL         string            `json:"image_url"`
			ImageBase64      string            `json:"image_base64"`
			CharWhitelist    string            `json:"char_whitelist"`
			CaptchaType      string            `json:"captcha_type"`
			SiteKey          string            `json:"site_key"`
			Action           string            `json:"action"`
			MinScore         string            `json:"min_score"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
		}
		mode := strings.ToLower(strings.TrimSpace(a.Mode))
		if mode == "" {
			mode = "form"
		}
		timeout := time.Duration(a.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}
		if timeout > 15*time.Minute {
			timeout = 15 * time.Minute
		}

		switch mode {
		case "ocr":
			img, err := s.captchaImageBytes(ctx, a.ImageURL, a.ImageBase64, a.Proxy)
			if err != nil {
				return jsonResult(map[string]any{"error": err.Error()})
			}
			res, err := captcha.SolveImageCaptcha(ctx, img, captcha.OCRRequest{CharWhitelist: a.CharWhitelist})
			if err != nil {
				return jsonResult(map[string]any{"error": err.Error()})
			}
			return jsonResult(res)

		case "token":
			solver := captcha.NewTokenSolver(s.captchaAPIKey(), s.captchaBaseURL(), nil)
			token, err := solver.Solve(ctx, captcha.TokenRequest{
				Type:     a.CaptchaType,
				SiteKey:  a.SiteKey,
				PageURL:  a.PageURL,
				Action:   a.Action,
				MinScore: a.MinScore,
				Proxy:    a.Proxy,
			})
			if err != nil {
				return jsonResult(map[string]any{"error": err.Error()})
			}
			return jsonResult(map[string]any{
				"solved":       true,
				"token":        token,
				"inject_js":    captcha.InjectJS(a.CaptchaType, token),
				"instructions": "Evaluate inject_js in the page (browser_inspect / Playwright) to fill the response field and fire the widget callback, then submit the form.",
			})

		default: // form
			if strings.TrimSpace(a.PageURL) == "" {
				return actool.Errorf("page_url is required for mode=form"), nil
			}
			req := captcha.FormSolveRequest{
				PageURL:          a.PageURL,
				FormAction:       a.FormAction,
				Method:           a.Method,
				CaptchaImageURL:  a.CaptchaImageURL,
				CaptchaField:     a.CaptchaField,
				CaptchaHashField: a.CaptchaHashField,
				ExtraFields:      a.ExtraFields,
				SuccessMarkers:   a.SuccessMarkers,
				FailureMarkers:   a.FailureMarkers,
				RejectMarkers:    a.RejectMarkers,
				MaxAttempts:      a.MaxAttempts,
				Delay:            time.Duration(a.DelaySeconds * float64(time.Second)),
				Timeout:          timeout,
				ProxyURL:         a.Proxy,
				OCR:              captcha.OCRRequest{CharWhitelist: a.CharWhitelist},
			}
			res, err := captcha.SolveForm(ctx, req)
			if err != nil && res.ElapsedMS == 0 {
				return jsonResult(map[string]any{"error": err.Error()})
			}
			out := map[string]any{}
			b, _ := json.Marshal(res)
			_ = json.Unmarshal(b, &out)
			return jsonResult(out)
		}
	}
}

// captchaImageBytes resolves the ocr-mode image from URL or base64.
func (s *Server) captchaImageBytes(ctx context.Context, imageURL, imageBase64, proxy string) ([]byte, error) {
	if strings.TrimSpace(imageBase64) != "" {
		raw := strings.TrimSpace(imageBase64)
		if i := strings.Index(raw, "base64,"); i >= 0 {
			raw = raw[i+len("base64,"):]
		}
		return base64.StdEncoding.DecodeString(raw)
	}
	if strings.TrimSpace(imageURL) == "" {
		return nil, fmt.Errorf("image_url or image_base64 is required for mode=ocr")
	}
	client, err := captcha.NewFormClient(60*time.Second, proxy, false)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return data, nil
}
