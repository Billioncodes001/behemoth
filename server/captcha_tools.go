package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/behemoth/server/captcha"
	actool "github.com/Autumn-27/norma/tool"
)

// CAPTCHA solving agent tools + Settings API.
// Supports classic image CAPTCHAs (via 2Captcha ImageToTextTask + fast local Tesseract OCR),
// Cloudflare Turnstile (standalone widgets & Cloudflare Challenge interstitials),
// reCAPTCHA v2 (standard, invisible, enterprise), reCAPTCHA v3, and hCaptcha.

// captchaTools returns the captcha agent tools.
func (s *Server) captchaTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolSolveCaptcha()}
}

// captchaAPIKey resolves the 2Captcha solving-service key: settings override first, then env.
func (s *Server) captchaAPIKey() string {
	if s != nil && s.m != nil && s.m.pg != nil {
		for _, k := range []string{"captcha_api_key", "twocaptcha_api_key"} {
			if v, ok, _ := s.m.pg.GetSetting(k); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	for _, env := range []string{"TWO_CAPTCHA_API_KEY", "CAPTCHA_API_KEY"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	return ""
}

// captchaBaseURL resolves the service base URL (defaults to official 2Captcha v2 API).
func (s *Server) captchaBaseURL() string {
	if s != nil && s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting("captcha_base_url"); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if v := strings.TrimSpace(os.Getenv("CAPTCHA_BASE_URL")); v != "" {
		return v
	}
	return "https://api.2captcha.com"
}

// toolSolveCaptcha exposes solve_captcha to agents.
func (s *Server) toolSolveCaptcha() actool.CoreTool {
	return roTool("solve_captcha",
		"Solve CAPTCHAs cleanly without burning LLM tokens: "+
			"mode='image' solves distorted/math/text Image CAPTCHAs via 2Captcha ImageToTextTask (accepts image_url, image_path, or image_base64); "+
			"mode='token' solves Cloudflare Turnstile (standalone widgets & Cloudflare Challenge pages), reCAPTCHA v2 (standard/invisible/enterprise), reCAPTCHA v3, and hCaptcha via 2Captcha and returns both the token and ready-to-evaluate browser inject_js; "+
			"mode='form' runs an automated fetch -> solve (local OCR + automatic 2Captcha Image fallback when key is configured) -> submit -> verify loop; "+
			"mode='ocr' reads an image via local Tesseract (+ optional 2Captcha fallback). ALWAYS call this tool instead of trying to read CAPTCHA images with LLM vision.",
		objSchema(map[string]any{
			"mode": map[string]any{
				"type":        "string",
				"enum":        []string{"form", "image", "ocr", "token"},
				"description": "form = full auto-solve HTTP form loop (default); image = solve one Image CAPTCHA via 2Captcha ImageToTextTask; token = solve Cloudflare Turnstile / reCAPTCHA v2 / reCAPTCHA v3 / hCaptcha via 2Captcha; ocr = local Tesseract OCR (+ 2Captcha fallback)",
			},
			"captcha_type": map[string]any{
				"type":        "string",
				"enum":        []string{"turnstile", "recaptcha_v2", "recaptcha_v3", "hcaptcha", "image"},
				"description": "Widget/CAPTCHA type: turnstile (Cloudflare Turnstile or Challenge), recaptcha_v2, recaptcha_v3, hcaptcha, or image",
			},
			"page_url":           strParam("Target page URL containing the CAPTCHA form or widget (required for mode=form and mode=token)"),
			"site_key":           strParam("mode=token: widget sitekey (data-sitekey / k= / render= / Turnstile 0x4... sitekey)"),
			"action":             strParam("mode=token: action name for reCAPTCHA v3 (pageAction) or Cloudflare Challenge Turnstile"),
			"min_score":          strParam("mode=token (recaptcha_v3): minimum score threshold e.g. '0.5', '0.7', or '0.9'"),
			"invisible":          map[string]any{"type": "boolean", "description": "mode=token (recaptcha_v2 / hcaptcha): set true for invisible widgets"},
			"enterprise":         map[string]any{"type": "boolean", "description": "mode=token (recaptcha_v2 / recaptcha_v3): set true for Google reCAPTCHA Enterprise"},
			"data_s":             strParam("mode=token: optional data-s value (reCAPTCHA v2) or rqdata (hCaptcha)"),
			"cdata":              strParam("mode=token (turnstile): optional cData parameter for Cloudflare Challenge pages"),
			"chl_page_data":      strParam("mode=token (turnstile): optional chlPageData / pagedata parameter for Cloudflare Challenge pages"),
			"user_agent":         strParam("Optional browser User-Agent (recommended when solving Cloudflare Challenge Turnstile)"),
			"image_url":          strParam("mode=image/ocr: URL of the CAPTCHA image to fetch and solve"),
			"image_path":         strParam("mode=image/ocr: local filesystem path to a saved CAPTCHA image (e.g. screenshot/curl output)"),
			"image_base64":       strParam("mode=image/ocr: base64 (or data:image/...) encoded CAPTCHA image"),
			"use_2captcha":       map[string]any{"type": "boolean", "description": "mode=ocr/form: force 2Captcha ImageToTextTask solving immediately when 2Captcha API key is configured"},
			"case_sensitive":     map[string]any{"type": "boolean", "description": "mode=image: whether the image CAPTCHA is case-sensitive"},
			"numeric":            map[string]any{"type": "integer", "description": "mode=image: 0 = any chars (default), 1 = digits only, 2 = letters only"},
			"math":               map[string]any{"type": "boolean", "description": "mode=image: set true when the image shows an arithmetic calculation (e.g. '7 + 4 = ?')"},
			"comment":            strParam("mode=image: optional instruction for 2Captcha solver (e.g. 'enter only red characters')"),
			"char_whitelist":     strParam("mode=ocr/form: restrict local OCR to these characters"),
			"form_action":        strParam("mode=form: optional explicit form action (auto-discovered from HTML when omitted)"),
			"method":             strParam("mode=form: optional HTTP method (POST by default)"),
			"captcha_image_url":  strParam("mode=form: explicit CAPTCHA image URL (auto-discovered when omitted)"),
			"captcha_field":      strParam("mode=form: answer input name (auto-discovered when omitted)"),
			"captcha_hash_field": strParam("mode=form: hidden challenge-key input name (e.g. captcha_0)"),
			"extra_fields":       map[string]any{"type": "object", "description": "mode=form: additional form fields to submit, e.g. {\"username\":\"admin\",\"password\":\"x\"}"},
			"success_contains":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "mode=form: case-insensitive body substrings indicating CAPTCHA acceptance"},
			"failure_contains":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "mode=form: case-insensitive body substrings indicating CAPTCHA rejection"},
			"reject_contains":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "mode=form: permanent non-CAPTCHA rejections (e.g. 'email already registered') that stop retries"},
			"max_attempts":       map[string]any{"type": "integer", "description": "mode=form: max rounds (default 25, max 200)"},
			"delay_seconds":      map[string]any{"type": "number", "description": "mode=form: pause between attempts (default 1s)"},
			"timeout_seconds":    map[string]any{"type": "integer", "description": "overall run timeout (default 300s, max 900s)"},
			"proxy":              strParam("optional proxy URL (http://user:pass@host:port) for requests"),
		}),
		solveCaptchaRun(s))
}

// solveCaptchaRun implements the solve_captcha execution.
func solveCaptchaRun(s *Server) func(context.Context, json.RawMessage) (actool.Result, error) {
	return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Mode             string            `json:"mode"`
			CaptchaType      string            `json:"captcha_type"`
			PageURL          string            `json:"page_url"`
			SiteKey          string            `json:"site_key"`
			Action           string            `json:"action"`
			MinScore         string            `json:"min_score"`
			Invisible        bool              `json:"invisible"`
			Enterprise       bool              `json:"enterprise"`
			DataS            string            `json:"data_s"`
			CData            string            `json:"cdata"`
			ChlPageData      string            `json:"chl_page_data"`
			UserAgent        string            `json:"user_agent"`
			ImageURL         string            `json:"image_url"`
			ImagePath        string            `json:"image_path"`
			ImageBase64      string            `json:"image_base64"`
			Use2Captcha      bool              `json:"use_2captcha"`
			CaseSensitive    bool              `json:"case_sensitive"`
			Numeric          int               `json:"numeric"`
			Math             bool              `json:"math"`
			Comment          string            `json:"comment"`
			CharWhitelist    string            `json:"char_whitelist"`
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
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
		}
		mode := strings.ToLower(strings.TrimSpace(a.Mode))
		cType := strings.ToLower(strings.TrimSpace(a.CaptchaType))
		if mode == "" {
			switch {
			case cType == "image" || a.ImagePath != "" || a.ImageBase64 != "" || a.ImageURL != "":
				if s.captchaAPIKey() != "" {
					mode = "image"
				} else {
					mode = "ocr"
				}
			case cType != "" && cType != "image":
				mode = "token"
			default:
				mode = "form"
			}
		}
		if mode == "token" && cType == "image" {
			mode = "image"
		}

		timeout := time.Duration(a.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}
		if timeout > 15*time.Minute {
			timeout = 15 * time.Minute
		}

		// Enforce Zero-IP-Leak & Fail-Closed Proxy Guard for target-facing CAPTCHA requests
		// (fetching target pages/images in mode=form, image, or ocr).
		needsTargetFetch := mode == "form" || ((mode == "ocr" || mode == "image") && strings.TrimSpace(a.ImageURL) != "" && strings.TrimSpace(a.ImageBase64) == "" && strings.TrimSpace(a.ImagePath) == "")
		effectiveProxy := strings.TrimSpace(a.Proxy)
		usedManagedProxy := false
		if effectiveProxy == "" && s != nil && s.m != nil {
			if s.m.IsProxyPoolFailClosed() && strings.TrimSpace(s.m.GlobalProxy()) == "" && needsTargetFetch {
				fcErr := fmt.Errorf("BEHEMOTH Fail-Closed Proxy Guard: all proxies in the enabled Proxy Pool are unhealthy; direct CAPTCHA request blocked")
				s.handleProxyToolFailure(ctx, fcErr)
				return jsonResult(map[string]any{"error": fcErr.Error()})
			}
			if out := strings.TrimSpace(s.m.OutboundProxyAddr()); out != "" {
				effectiveProxy = out
				usedManagedProxy = true
			} else if gp := strings.TrimSpace(s.m.GlobalProxy()); gp != "" {
				effectiveProxy = gp
				usedManagedProxy = true
			}
		}

		apiKey := s.captchaAPIKey()
		baseURL := s.captchaBaseURL()

		switch mode {
		case "image":
			imgURL := a.ImageURL
			if imgURL == "" {
				imgURL = a.CaptchaImageURL
			}
			img, err := s.captchaImageBytes(ctx, imgURL, a.ImagePath, a.ImageBase64, effectiveProxy)
			if err != nil {
				if usedManagedProxy {
					s.handleProxyToolFailure(ctx, err)
				}
				return jsonResult(map[string]any{"error": err.Error()})
			}
			if apiKey != "" {
				solver := captcha.NewTokenSolver(apiKey, baseURL, nil)
				imgRes, serr := solver.SolveImage(ctx, captcha.ImageSolveRequest{
					ImageBytes:    img,
					CaseSensitive: a.CaseSensitive,
					Numeric:       a.Numeric,
					Math:          a.Math,
					Comment:       a.Comment,
				})
				if serr == nil && imgRes.Text != "" {
					return jsonResult(map[string]any{
						"solved":     true,
						"provider":   "2captcha",
						"answer":     imgRes.Text,
						"candidates": []string{imgRes.Text},
						"task_id":    imgRes.TaskID,
					})
				}
				if serr != nil {
					// Fall back to local OCR if 2Captcha returned a transient error, surfacing warning.
					ocrRes, oerr := captcha.SolveImageCaptcha(ctx, img, captcha.OCRRequest{CharWhitelist: a.CharWhitelist})
					if oerr == nil && len(ocrRes.Candidates) > 0 {
						return jsonResult(map[string]any{
							"solved":           true,
							"provider":         "local_ocr_fallback",
							"answer":           ocrRes.Candidates[0],
							"candidates":       ocrRes.Candidates,
							"twocaptcha_error": serr.Error(),
						})
					}
					return jsonResult(map[string]any{"error": serr.Error()})
				}
			}
			ocrRes, oerr := captcha.SolveImageCaptcha(ctx, img, captcha.OCRRequest{CharWhitelist: a.CharWhitelist})
			if oerr != nil {
				return jsonResult(map[string]any{"error": oerr.Error(), "hint": "Configure 2Captcha API key in System -> Settings -> Network and tools for reliable Image CAPTCHA solving."})
			}
			best := ""
			if len(ocrRes.Candidates) > 0 {
				best = ocrRes.Candidates[0]
			}
			return jsonResult(map[string]any{
				"solved":     best != "",
				"provider":   "local_ocr",
				"answer":     best,
				"candidates": ocrRes.Candidates,
			})

		case "ocr":
			imgURL := a.ImageURL
			if imgURL == "" {
				imgURL = a.CaptchaImageURL
			}
			img, err := s.captchaImageBytes(ctx, imgURL, a.ImagePath, a.ImageBase64, effectiveProxy)
			if err != nil {
				if usedManagedProxy {
					s.handleProxyToolFailure(ctx, err)
				}
				return jsonResult(map[string]any{"error": err.Error()})
			}
			if a.Use2Captcha && apiKey != "" {
				solver := captcha.NewTokenSolver(apiKey, baseURL, nil)
				if imgRes, serr := solver.SolveImage(ctx, captcha.ImageSolveRequest{
					ImageBytes:    img,
					CaseSensitive: a.CaseSensitive,
					Numeric:       a.Numeric,
					Math:          a.Math,
					Comment:       a.Comment,
				}); serr == nil && imgRes.Text != "" {
					return jsonResult(map[string]any{
						"provider":   "2captcha",
						"answer":     imgRes.Text,
						"candidates": []string{imgRes.Text},
						"task_id":    imgRes.TaskID,
					})
				}
			}
			res, err := captcha.SolveImageCaptcha(ctx, img, captcha.OCRRequest{CharWhitelist: a.CharWhitelist})
			if (err != nil || len(res.Candidates) == 0) && apiKey != "" {
				solver := captcha.NewTokenSolver(apiKey, baseURL, nil)
				if imgRes, serr := solver.SolveImage(ctx, captcha.ImageSolveRequest{
					ImageBytes:    img,
					CaseSensitive: a.CaseSensitive,
					Numeric:       a.Numeric,
					Math:          a.Math,
					Comment:       a.Comment,
				}); serr == nil && imgRes.Text != "" {
					return jsonResult(map[string]any{
						"provider":   "2captcha",
						"answer":     imgRes.Text,
						"candidates": []string{imgRes.Text},
						"task_id":    imgRes.TaskID,
					})
				}
			}
			if err != nil {
				return jsonResult(map[string]any{"error": err.Error()})
			}
			return jsonResult(res)

		case "token":
			solver := captcha.NewTokenSolver(apiKey, baseURL, nil)
			sol, err := solver.SolveDetailed(ctx, captcha.TokenRequest{
				Type:        a.CaptchaType,
				SiteKey:     a.SiteKey,
				PageURL:     a.PageURL,
				Action:      a.Action,
				MinScore:    a.MinScore,
				Invisible:   a.Invisible,
				Enterprise:  a.Enterprise,
				DataS:       a.DataS,
				CData:       a.CData,
				ChlPageData: a.ChlPageData,
				UserAgent:   a.UserAgent,
				Proxy:       a.Proxy,
			})
			if err != nil {
				return jsonResult(map[string]any{"error": err.Error()})
			}
			out := map[string]any{
				"solved":       true,
				"provider":     "2captcha",
				"captcha_type": a.CaptchaType,
				"token":        sol.Token,
				"task_id":      sol.TaskID,
				"inject_js":    captcha.InjectJS(a.CaptchaType, sol.Token),
				"instructions": "Evaluate inject_js in the page (browser_inspect / Playwright) to populate g-recaptcha-response / cf-turnstile-response / h-captcha-response and invoke the widget callback, or submit the token directly in the POST form/JSON body.",
			}
			if sol.UserAgent != "" {
				out["user_agent"] = sol.UserAgent
			}
			return jsonResult(out)

		default: // form
			if strings.TrimSpace(a.PageURL) == "" {
				return actool.Errorf("page_url is required for mode=form"), nil
			}
			var roundCounter int32
			var customRec captcha.Recognizer
			if apiKey != "" {
				solver := captcha.NewTokenSolver(apiKey, baseURL, nil)
				customRec = func(rctx context.Context, imgBytes []byte) ([]string, error) {
					n := atomic.AddInt32(&roundCounter, 1)
					// Try fast local OCR on rounds 1-2 unless use_2captcha=true; escalate to 2Captcha ImageToText on round 3+ or OCR miss.
					if !a.Use2Captcha && n <= 2 {
						if r, oerr := captcha.SolveImageCaptcha(rctx, imgBytes, captcha.OCRRequest{CharWhitelist: a.CharWhitelist}); oerr == nil && len(r.Candidates) > 0 {
							return r.Candidates, nil
						}
					}
					imgRes, serr := solver.SolveImage(rctx, captcha.ImageSolveRequest{
						ImageBytes:    imgBytes,
						CaseSensitive: a.CaseSensitive,
						Numeric:       a.Numeric,
						Math:          a.Math,
						Comment:       a.Comment,
					})
					if serr == nil && imgRes.Text != "" {
						return []string{imgRes.Text}, nil
					}
					r, oerr := captcha.SolveImageCaptcha(rctx, imgBytes, captcha.OCRRequest{CharWhitelist: a.CharWhitelist})
					if oerr != nil {
						if serr != nil {
							return nil, serr
						}
						return nil, oerr
					}
					return r.Candidates, nil
				}
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
				ProxyURL:         effectiveProxy,
				OCR:              captcha.OCRRequest{CharWhitelist: a.CharWhitelist},
				Recognizer:       customRec,
			}
			res, err := captcha.SolveForm(ctx, req)
			if err != nil && usedManagedProxy {
				s.handleProxyToolFailure(ctx, err)
			}
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

// captchaImageBytes resolves the image from base64, local path, or URL.
func (s *Server) captchaImageBytes(ctx context.Context, imageURL, imagePath, imageBase64, proxy string) ([]byte, error) {
	if strings.TrimSpace(imageBase64) != "" {
		raw := strings.TrimSpace(imageBase64)
		if i := strings.Index(raw, "base64,"); i >= 0 {
			raw = raw[i+len("base64,"):]
		}
		return base64.StdEncoding.DecodeString(raw)
	}
	if strings.TrimSpace(imagePath) != "" {
		return os.ReadFile(strings.TrimSpace(imagePath))
	}
	if strings.TrimSpace(imageURL) == "" {
		return nil, fmt.Errorf("image_url, image_path, or image_base64 is required")
	}
	client, err := captcha.NewFormClient(60*time.Second, proxy, false)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
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

// ==================== 2Captcha Settings & Test REST Handlers ====================

// handleCaptchaStatus returns current 2Captcha & local OCR status for System Settings.
func (s *Server) handleCaptchaStatus(w http.ResponseWriter, r *http.Request) {
	key := s.captchaAPIKey()
	baseURL := s.captchaBaseURL()
	_, tessErr := exec.LookPath("tesseract")
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":          key != "",
		"provider":            "2captcha",
		"base_url":            baseURL,
		"local_ocr_available": tessErr == nil,
		"capabilities": map[string]bool{
			"image":        key != "" || tessErr == nil,
			"turnstile":    key != "",
			"recaptcha_v2": key != "",
			"recaptcha_v3": key != "",
			"hcaptcha":     key != "",
		},
	})
}

// handleCaptchaConfig saves the 2Captcha API key (and optional base URL) to PostgreSQL settings.
func (s *Server) handleCaptchaConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		APIKey  *string `json:"api_key"`
		BaseURL *string `json:"base_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "database not initialized")
		return
	}
	if req.APIKey != nil {
		val := strings.TrimSpace(*req.APIKey)
		if err := s.m.pg.SetSetting("captcha_api_key", val); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to save captcha_api_key: "+err.Error())
			return
		}
	}
	if req.BaseURL != nil {
		u := strings.TrimRight(strings.TrimSpace(*req.BaseURL), "/")
		if err := s.m.pg.SetSetting("captcha_base_url", u); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to save captcha_base_url: "+err.Error())
			return
		}
	}
	log.Printf("[captcha] Updated 2Captcha configuration (configured=%v)", s.captchaAPIKey() != "")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"configured": s.captchaAPIKey() != "",
		"base_url":   s.captchaBaseURL(),
	})
}

// handleCaptchaTest verifies the 2Captcha API key against 2Captcha's getBalance endpoint.
func (s *Server) handleCaptchaTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		APIKey  string `json:"api_key"`
		BaseURL string `json:"base_url"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	apiKey := strings.TrimSpace(req.APIKey)
	if apiKey == "" {
		apiKey = s.captchaAPIKey()
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL == "" {
		baseURL = s.captchaBaseURL()
	}
	if apiKey == "" {
		writeErr(w, http.StatusBadRequest, "2Captcha API key is not configured — please enter and save your API key first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	solver := captcha.NewTokenSolver(apiKey, baseURL, nil)
	balance, err := solver.CheckBalance(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": "2captcha",
		"balance":  balance,
	})
}

// serviceEnvPairs returns the live environment variables injected into every agent
// tool execution (Bash, Python scripts, CLI tools) so running and newly spawned
// agents immediately pick up configured 2Captcha and Multi-Engine Search keys/URLs.
func (s *Server) serviceEnvPairs() []string {
	if s == nil {
		return nil
	}
	var env []string
	if capKey := s.captchaAPIKey(); capKey != "" {
		env = append(env,
			"TWO_CAPTCHA_API_KEY="+capKey,
			"CAPTCHA_API_KEY="+capKey,
			"CAPTCHA_BASE_URL="+s.captchaBaseURL(),
		)
	}
	if s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting("search_firecrawl_api_key"); ok && strings.TrimSpace(v) != "" {
			k := strings.TrimSpace(v)
			env = append(env, "SEARCH_FIRECRAWL_API_KEY="+k, "FIRECRAWL_API_KEY="+k)
		} else if v := strings.TrimSpace(os.Getenv("SEARCH_FIRECRAWL_API_KEY")); v != "" {
			env = append(env, "SEARCH_FIRECRAWL_API_KEY="+v, "FIRECRAWL_API_KEY="+v)
		}
		if v, ok, _ := s.m.pg.GetSetting("search_firecrawl_base_url"); ok && strings.TrimSpace(v) != "" {
			env = append(env, "SEARCH_FIRECRAWL_URL="+strings.TrimSpace(v))
		}
		if v, ok, _ := s.m.pg.GetSetting("search_tavily_api_key"); ok && strings.TrimSpace(v) != "" {
			k := strings.TrimSpace(v)
			env = append(env, "SEARCH_TAVILY_API_KEY="+k, "TAVILY_API_KEY="+k)
		} else if v := strings.TrimSpace(os.Getenv("SEARCH_TAVILY_API_KEY")); v != "" {
			env = append(env, "SEARCH_TAVILY_API_KEY="+v, "TAVILY_API_KEY="+v)
		}
		if v, ok, _ := s.m.pg.GetSetting("search_brave_api_key"); ok && strings.TrimSpace(v) != "" {
			k := strings.TrimSpace(v)
			env = append(env, "SEARCH_BRAVE_API_KEY="+k, "BRAVE_API_KEY="+k)
		} else if v := strings.TrimSpace(os.Getenv("SEARCH_BRAVE_API_KEY")); v != "" {
			env = append(env, "SEARCH_BRAVE_API_KEY="+v, "BRAVE_API_KEY="+v)
		}
	}
	if s.searchOrchestrator != nil {
		stats := s.searchOrchestrator.GetStats()
		if sxURL, _ := stats["searxng_url"].(string); strings.TrimSpace(sxURL) != "" {
			env = append(env, "SEARCH_SEARXNG_URL="+strings.TrimSpace(sxURL))
		}
	}
	return env
}

// serviceIntegrationsNote builds the live runtime prompt guidance injected into all
// agents so they always know which CAPTCHA & Search services/keys are active and
// how to invoke them (both via native tools and Bash/Python environment variables).
func (s *Server) serviceIntegrationsNote() string {
	if s == nil {
		return ""
	}
	capConfigured := s.captchaAPIKey() != ""
	capStatus := "UNCONFIGURED (local Tesseract OCR active; add 2Captcha key in System -> Settings -> Network and tools for Turnstile/reCAPTCHA/distorted Image CAPTCHAs)"
	if capConfigured {
		capStatus = "ACTIVE (2Captcha key configured — live in `solve_captcha` AND `$TWO_CAPTCHA_API_KEY` / `$CAPTCHA_API_KEY` in Bash)"
	}

	var activeEngines []string
	if s.searchOrchestrator != nil {
		stats := s.searchOrchestrator.GetStats()
		if em, ok := stats["engine_status"].(map[string]bool); ok {
			for _, pair := range []struct {
				k, label string
			}{
				{"tavily", "Tavily AI (`engine='tavily'`, `$SEARCH_TAVILY_API_KEY`)"},
				{"firecrawl", "Firecrawl Search & Crawl (`engine='firecrawl'`, `$SEARCH_FIRECRAWL_API_KEY`)"},
				{"brave", "Brave Search (`engine='brave'`, `$SEARCH_BRAVE_API_KEY`)"},
				{"searxng", "SearXNG Local Meta-Search (`engine='searxng'`, `$SEARCH_SEARXNG_URL`)"},
				{"sploitus", "Sploitus Exploit DB (`exploit_search` / `engine='sploitus'`)"},
				{"duckduckgo", "DuckDuckGo (`engine='duckduckgo'`)"},
			} {
				if em[pair.k] {
					activeEngines = append(activeEngines, pair.label)
				}
			}
		}
	}
	enginesSummary := "DuckDuckGo, Sploitus"
	if len(activeEngines) > 0 {
		enginesSummary = strings.Join(activeEngines, ", ")
	}

	return "\n\n**Configured Platform CAPTCHA & Search Services (Auto-Loaded Live)**:\n" +
		"- **2Captcha & CAPTCHA Solver (`solve_captcha`)**: " + capStatus + ".\n" +
		"  - **When & How to Use**: NEVER attempt to read CAPTCHA images with LLM vision or manual loops. Always call `solve_captcha`:\n" +
		"    1. **Image CAPTCHAs** (distorted text, digits, math): `solve_captcha(mode=\"image\", image_url=...|image_path=...|image_base64=..., math=..., case_sensitive=...)` or full form auto-submit `solve_captcha(mode=\"form\", page_url=..., extra_fields={...})`.\n" +
		"    2. **Cloudflare Turnstile & Challenge Pages**: `solve_captcha(mode=\"token\", captcha_type=\"turnstile\", site_key=\"0x4...\", page_url=..., action=..., cdata=..., chl_page_data=..., user_agent=...)` — evaluate the returned `inject_js` in `browser_inspect`/Playwright or post `cf-turnstile-response`.\n" +
		"    3. **reCAPTCHA v2 (Checkbox / Invisible / Enterprise)**: `solve_captcha(mode=\"token\", captcha_type=\"recaptcha_v2\", site_key=..., page_url=..., invisible=true|false, enterprise=true|false, data_s=...)`.\n" +
		"    4. **reCAPTCHA v3 (Score-Based)**: `solve_captcha(mode=\"token\", captcha_type=\"recaptcha_v3\", site_key=..., page_url=..., action=\"login\", min_score=\"0.7\", enterprise=true|false)`.\n" +
		"    5. **hCaptcha**: `solve_captcha(mode=\"token\", captcha_type=\"hcaptcha\", site_key=..., page_url=...)`.\n" +
		"  - **Custom Scripts in Bash/Python**: If writing a custom Playwright/Python solver workflow, read `$TWO_CAPTCHA_API_KEY` (or `$CAPTCHA_API_KEY`) and `$CAPTCHA_BASE_URL` directly from environment variables.\n" +
		"- **Multi-Engine Search & Crawl (`multi_engine_search` & `exploit_search`) — Currently Active**: " + enginesSummary + ".\n" +
		"  - **When to Pick Each Service**:\n" +
		"    - Call `multi_engine_search(query=..., mode=\"general\"|\"technical\"|\"osint\"|\"exploit\")` for automatic multi-engine fallback, or pin `engine=` for specific strengths:\n" +
		"    - **`searxng`**: Self-hosted locally on this server (`$SEARCH_SEARXNG_URL`, zero API cost/rate limits) — best for high-volume OSINT, subdomain/endpoint dorking, and parallel queries.\n" +
		"    - **`tavily`**: AI-ranked technical search (`$SEARCH_TAVILY_API_KEY`) — best for vendor security advisories, framework internals, and CVE root-cause writeups.\n" +
		"    - **`firecrawl`**: Search + JS-rendered clean Markdown scraping (`$SEARCH_FIRECRAWL_API_KEY`) — use `engine='firecrawl'` for search, or call Firecrawl's `/v1/scrape` API with `Authorization: Bearer $FIRECRAWL_API_KEY` in `Bash`/Python when extracting clean Markdown from complex SPAs/docs.\n" +
		"    - **`brave`**: Independent web index (`$SEARCH_BRAVE_API_KEY`) — best for `site:target.com` dorking without CAPTCHA blocks.\n" +
		"    - **`sploitus` / `exploit_search`**: Best for public CVE PoCs, GitHub exploit repos, and Exploit-DB.\n" +
		"  - **Credential Hygiene**: Platform keys (`$TWO_CAPTCHA_API_KEY`, `$SEARCH_*_API_KEY`) are strictly for calling their respective APIs — NEVER send platform API keys to target hosts or print raw keys in reports."
}
