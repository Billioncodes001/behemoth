package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Token solving for modern, invisible captchas (reCAPTCHA v2/v3, hCaptcha,
// Cloudflare Turnstile) through a 2Captcha-compatible solving service. The
// returned token is injected into the page's response field and callback.

// TokenSolver talks to a 2Captcha-compatible API (2captcha.com, rucaptcha.com,
// capsolver's compat endpoint, self-hosted solvers exposing the same contract).
type TokenSolver struct {
	APIKey  string
	BaseURL string // default https://2captcha.com
	Client  *http.Client
}

// TokenRequest describes one token job.
type TokenRequest struct {
	// Type is one of recaptcha_v2 | recaptcha_v3 | hcaptcha | turnstile.
	Type    string
	SiteKey string
	PageURL string
	// Action / MinScore apply to reCAPTCHA v3.
	Action   string
	MinScore string
	// Invisible marks invisible reCAPTCHA v2 widgets.
	Invisible bool
	// UserAgent / Proxy / ProxyType / ProxyLogin / ProxyPassword are optional
	// and forwarded to the service.
	UserAgent   string
	Proxy       string
	ProxyType   string
	ProxyLogin  string
	ProxyPasswd string
	// PollInterval / MaxWait tune polling (defaults 5s / 180s).
	PollInterval time.Duration
	MaxWait      time.Duration
}

var validTokenTypes = map[string]string{
	"recaptcha_v2": "userrecaptcha",
	"recaptcha_v3": "userrecaptcha",
	"recaptcha":    "userrecaptcha",
	"hcaptcha":     "hcaptcha",
	"turnstile":    "turnstile",
}

// NewTokenSolver builds a solver with sane defaults.
func NewTokenSolver(apiKey, baseURL string, client *http.Client) *TokenSolver {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://2captcha.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &TokenSolver{APIKey: apiKey, BaseURL: baseURL, Client: client}
}

// InjectJS returns a browser-evaluable script that fills the response field for
// the solved widget and fires its callback (covers g-recaptcha-response,
// h-captcha-response and cf-turnstile-response).
func InjectJS(kind, token string) string {
	tok, _ := json.Marshal(token)
	return fmt.Sprintf(`(function(){
  var token = %s;
  var fields = ['g-recaptcha-response','h-captcha-response','cf-turnstile-response'];
  for (var i = 0; i < fields.length; i++) {
    var els = document.querySelectorAll('textarea[name="'+fields[i]+'"], input[name="'+fields[i]+'"], #'+fields[i]);
    for (var j = 0; j < els.length; j++) { els[j].value = token; els[j].innerHTML = token; els[j].textContent = token; }
  }
  try {
    if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {
      var walk = function(o){ if(!o || typeof o !== 'object') return; for (var k in o){ var v=o[k]; if (v && typeof v==='object'){ if (typeof v.callback==='function'){ v.callback(token); } walk(v);} } };
      walk(window.___grecaptcha_cfg.clients);
    }
    var cb = window.captchaSuccessCallback || window.onTurnstileSuccess || window.hcaptchaSuccess;
    if (typeof cb === 'function') { cb(token); }
  } catch (e) {}
  return true;
})()`, tok)
}

// Solve submits the job and polls until the token is ready.
func (s *TokenSolver) Solve(ctx context.Context, req TokenRequest) (string, error) {
	if s == nil || strings.TrimSpace(s.APIKey) == "" {
		return "", errors.New("captcha service API key is not configured (setting: captcha_api_key)")
	}
	method, ok := validTokenTypes[strings.ToLower(strings.TrimSpace(req.Type))]
	if !ok {
		return "", fmt.Errorf("unsupported captcha type %q (want recaptcha_v2, recaptcha_v3, hcaptcha or turnstile)", req.Type)
	}
	if strings.TrimSpace(req.SiteKey) == "" || strings.TrimSpace(req.PageURL) == "" {
		return "", errors.New("site_key and page_url are required")
	}
	if req.PollInterval <= 0 {
		req.PollInterval = 5 * time.Second
	}
	if req.MaxWait <= 0 {
		req.MaxWait = 180 * time.Second
	}

	params := url.Values{}
	params.Set("key", s.APIKey)
	params.Set("method", method)
	params.Set("json", "1")
	params.Set("sitekey", req.SiteKey)
	params.Set("pageurl", req.PageURL)
	if req.Type == "recaptcha_v3" {
		if req.Action != "" {
			params.Set("action", req.Action)
		}
		if req.MinScore != "" {
			params.Set("min_score", req.MinScore)
		}
	}
	if req.Invisible {
		params.Set("invisible", "1")
	}
	if req.UserAgent != "" {
		params.Set("userAgent", req.UserAgent)
	}
	if req.Proxy != "" {
		params.Set("proxy", req.Proxy)
		params.Set("proxytype", firstNonEmptyStr(req.ProxyType, "HTTP"))
		if req.ProxyLogin != "" || req.ProxyPasswd != "" {
			params.Set("proxylogin", req.ProxyLogin)
			params.Set("proxypassword", req.ProxyPasswd)
		}
	}

	var jobID string
	{
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		data, err := s.post(cctx, "/in.php", params)
		if err != nil {
			return "", err
		}
		var in struct {
			Status  int    `json:"status"`
			Request string `json:"request"`
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return "", fmt.Errorf("submit captcha job: %w", err)
		}
		if in.Status != 1 {
			return "", fmt.Errorf("captcha submit failed: %s", in.Request)
		}
		jobID = in.Request
	}

	deadline := time.Now().Add(req.MaxWait)
	get := url.Values{}
	get.Set("key", s.APIKey)
	get.Set("action", "get")
	get.Set("json", "1")
	get.Set("id", jobID)
	for {
		time.Sleep(req.PollInterval)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("captcha solve timed out after %s", req.MaxWait)
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		data, err := s.post(cctx, "/res.php", get)
		cancel()
		if err != nil {
			continue // transient poll errors are retried until the deadline
		}
		var out struct {
			Status  int    `json:"status"`
			Request string `json:"request"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			continue
		}
		switch {
		case out.Status == 1:
			return out.Request, nil
		case strings.EqualFold(out.Request, "CAPCHA_NOT_READY"):
			continue
		default:
			return "", fmt.Errorf("captcha solve failed: %s", out.Request)
		}
	}
}

func (s *TokenSolver) post(ctx context.Context, path string, params url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+path, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
