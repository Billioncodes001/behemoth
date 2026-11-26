package captcha

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Token & Image solving for modern CAPTCHAs (Image CAPTCHA, Cloudflare Turnstile,
// reCAPTCHA v2 standard/invisible/enterprise, reCAPTCHA v3, and hCaptcha) through
// 2Captcha's official v2 JSON API (https://api.2captcha.com) with automatic
// fallback to legacy v1 (/in.php + /res.php) for 2Captcha-compatible endpoints.

// TokenSolver talks to 2Captcha (v2 JSON API + v1 compat) or any compatible endpoint.
type TokenSolver struct {
	APIKey  string
	BaseURL string // default https://api.2captcha.com
	Client  *http.Client
}

// TokenRequest describes one widget/token solving job.
type TokenRequest struct {
	// Type is one of turnstile | recaptcha_v2 | recaptcha_v3 | hcaptcha.
	Type    string
	SiteKey string
	PageURL string
	// Action / MinScore apply to reCAPTCHA v3 and Cloudflare Turnstile Challenge.
	Action   string
	MinScore string
	// Invisible / Enterprise / DataS / APIDomain apply to reCAPTCHA v2/v3 & hCaptcha.
	Invisible  bool
	Enterprise bool
	DataS      string
	APIDomain  string
	// CData / ChlPageData apply to Cloudflare Turnstile Challenge interstitials.
	CData       string
	ChlPageData string
	// UserAgent / Proxy / ProxyType / ProxyLogin / ProxyPassword are optional.
	UserAgent   string
	Proxy       string
	ProxyType   string
	ProxyLogin  string
	ProxyPasswd string
	// PollInterval / MaxWait tune polling (defaults 5s / 180s).
	PollInterval time.Duration
	MaxWait      time.Duration
}

// TokenSolveResult carries the solved token plus optional metadata returned by 2Captcha
// (such as the exact browser UserAgent required for Cloudflare Challenge clearance).
type TokenSolveResult struct {
	Token     string `json:"token"`
	UserAgent string `json:"user_agent,omitempty"`
	TaskID    string `json:"task_id,omitempty"`
}

// ImageSolveRequest describes an Image CAPTCHA job solved via 2Captcha ImageToTextTask.
type ImageSolveRequest struct {
	ImageBytes    []byte
	CaseSensitive bool
	// Numeric: 0 = any (default), 1 = digits only, 2 = letters only.
	Numeric      int
	Math         bool
	MinLength    int
	MaxLength    int
	Comment      string
	PollInterval time.Duration
	MaxWait      time.Duration
}

// ImageSolveResult carries the solved text from 2Captcha.
type ImageSolveResult struct {
	Text   string `json:"text"`
	TaskID string `json:"task_id,omitempty"`
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
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.2captcha.com"
	}
	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second}
	}
	return &TokenSolver{APIKey: strings.TrimSpace(apiKey), BaseURL: baseURL, Client: client}
}

func (s *TokenSolver) v2Endpoint() (string, bool) {
	u := strings.ToLower(strings.TrimRight(strings.TrimSpace(s.BaseURL), "/"))
	switch u {
	case "", "https://2captcha.com", "http://2captcha.com", "https://api.2captcha.com":
		return "https://api.2captcha.com", true
	case "https://rucaptcha.com", "https://api.rucaptcha.com":
		return "https://api.rucaptcha.com", true
	default:
		if strings.Contains(u, "api.2captcha.com") || strings.Contains(u, "api.rucaptcha.com") {
			return s.BaseURL, true
		}
		return "", false
	}
}

func (s *TokenSolver) v1Endpoint() string {
	u := strings.TrimRight(strings.TrimSpace(s.BaseURL), "/")
	switch strings.ToLower(u) {
	case "", "https://api.2captcha.com":
		return "https://2captcha.com"
	case "https://api.rucaptcha.com":
		return "https://rucaptcha.com"
	default:
		return u
	}
}

// InjectJS returns a browser-evaluable script that fills the response field for
// the solved widget and fires its callback (covers g-recaptcha-response,
// h-captcha-response, cf-turnstile-response, data-callback attributes, and
// Cloudflare Turnstile Challenge window.tsCallback).
func InjectJS(kind, token string) string {
	tok, _ := json.Marshal(token)
	return fmt.Sprintf(`(function(){
  var token = %s;
  var fields = ['g-recaptcha-response','h-captcha-response','cf-turnstile-response'];
  for (var i = 0; i < fields.length; i++) {
    var els = document.querySelectorAll('textarea[name="'+fields[i]+'"], input[name="'+fields[i]+'"], #'+fields[i]);
    for (var j = 0; j < els.length; j++) {
      els[j].value = token;
      els[j].innerHTML = token;
      els[j].textContent = token;
      els[j].dispatchEvent(new Event('input', { bubbles: true }));
      els[j].dispatchEvent(new Event('change', { bubbles: true }));
    }
  }
  try {
    var widgets = document.querySelectorAll('[data-callback]');
    for (var w = 0; w < widgets.length; w++) {
      var cbName = widgets[w].getAttribute('data-callback');
      if (cbName && typeof window[cbName] === 'function') { window[cbName](token); }
    }
    if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {
      var walk = function(o, depth){ if(!o || typeof o !== 'object' || depth > 6) return; for (var k in o){ var v=o[k]; if (v && typeof v==='object'){ if (typeof v.callback==='function'){ v.callback(token); } walk(v, depth+1);} } };
      walk(window.___grecaptcha_cfg.clients, 0);
    }
    var cb = window.tsCallback || window.turnstileCallback || window.onTurnstileSuccess || window.captchaSuccessCallback || window.hcaptchaSuccess;
    if (typeof cb === 'function') { cb(token); }
  } catch (e) {}
  return true;
})()`, tok)
}

// CheckBalance verifies the 2Captcha API key and returns the live account balance (USD).
func (s *TokenSolver) CheckBalance(ctx context.Context) (float64, error) {
	if s == nil || strings.TrimSpace(s.APIKey) == "" {
		return 0, errors.New("2Captcha API key is not configured")
	}
	if v2Base, ok := s.v2Endpoint(); ok {
		payload, _ := json.Marshal(map[string]string{"clientKey": s.APIKey})
		data, status, err := s.postJSON(ctx, v2Base+"/getBalance", payload)
		if err == nil && status != http.StatusNotFound {
			var resp struct {
				ErrorID          int     `json:"errorId"`
				ErrorCode        string  `json:"errorCode"`
				ErrorDescription string  `json:"errorDescription"`
				Balance          float64 `json:"balance"`
			}
			if jerr := json.Unmarshal(data, &resp); jerr == nil {
				if resp.ErrorID != 0 {
					msg := firstNonEmptyStr(resp.ErrorCode, resp.ErrorDescription, "invalid 2Captcha API key")
					return 0, fmt.Errorf("2Captcha error: %s", msg)
				}
				return resp.Balance, nil
			}
		}
	}

	params := url.Values{}
	params.Set("key", s.APIKey)
	params.Set("action", "getbalance")
	params.Set("json", "1")
	data, err := s.postForm(ctx, s.v1Endpoint()+"/res.php", params)
	if err != nil {
		return 0, err
	}
	var v1 struct {
		Status  int    `json:"status"`
		Request string `json:"request"`
	}
	if err := json.Unmarshal(data, &v1); err != nil {
		return 0, fmt.Errorf("parse balance response: %w", err)
	}
	if v1.Status != 1 {
		return 0, fmt.Errorf("2Captcha error: %s", v1.Request)
	}
	bal, err := strconv.ParseFloat(strings.TrimSpace(v1.Request), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid balance %q: %w", v1.Request, err)
	}
	return bal, nil
}

// SolveImage solves a classic distorted/math/text Image CAPTCHA via 2Captcha ImageToTextTask.
func (s *TokenSolver) SolveImage(ctx context.Context, req ImageSolveRequest) (ImageSolveResult, error) {
	if s == nil || strings.TrimSpace(s.APIKey) == "" {
		return ImageSolveResult{}, errors.New("2Captcha API key is not configured (set it in System -> Settings -> Network and tools)")
	}
	if len(req.ImageBytes) == 0 {
		return ImageSolveResult{}, errors.New("captcha image bytes are empty")
	}
	if req.PollInterval <= 0 {
		req.PollInterval = 3 * time.Second
	}
	if req.MaxWait <= 0 {
		req.MaxWait = 90 * time.Second
	}

	b64 := base64.StdEncoding.EncodeToString(req.ImageBytes)

	if v2Base, ok := s.v2Endpoint(); ok {
		task := map[string]any{
			"type": "ImageToTextTask",
			"body": b64,
		}
		if req.CaseSensitive {
			task["case"] = true
		}
		if req.Numeric > 0 {
			task["numeric"] = req.Numeric
		}
		if req.Math {
			task["math"] = true
		}
		if req.MinLength > 0 {
			task["minLength"] = req.MinLength
		}
		if req.MaxLength > 0 {
			task["maxLength"] = req.MaxLength
		}
		if strings.TrimSpace(req.Comment) != "" {
			task["comment"] = strings.TrimSpace(req.Comment)
		}
		sol, taskID, err := s.solveV2Task(ctx, v2Base, task, req.PollInterval, req.MaxWait)
		if err == nil {
			txt, _ := sol["text"].(string)
			return ImageSolveResult{Text: strings.TrimSpace(txt), TaskID: taskID}, nil
		}
		if !strings.Contains(err.Error(), "status 404") {
			return ImageSolveResult{}, err
		}
	}

	params := url.Values{}
	params.Set("key", s.APIKey)
	params.Set("method", "base64")
	params.Set("body", b64)
	params.Set("json", "1")
	if req.CaseSensitive {
		params.Set("regsense", "1")
	}
	if req.Numeric > 0 {
		params.Set("numeric", strconv.Itoa(req.Numeric))
	}
	if req.Math {
		params.Set("calc", "1")
	}
	if req.MinLength > 0 {
		params.Set("min_len", strconv.Itoa(req.MinLength))
	}
	if req.MaxLength > 0 {
		params.Set("max_len", strconv.Itoa(req.MaxLength))
	}
	if strings.TrimSpace(req.Comment) != "" {
		params.Set("textinstructions", strings.TrimSpace(req.Comment))
	}
	ans, taskID, err := s.solveV1Job(ctx, params, req.PollInterval, req.MaxWait)
	if err != nil {
		return ImageSolveResult{}, err
	}
	return ImageSolveResult{Text: strings.TrimSpace(ans), TaskID: taskID}, nil
}

// Solve submits a widget job and returns the solved token string.
func (s *TokenSolver) Solve(ctx context.Context, req TokenRequest) (string, error) {
	res, err := s.SolveDetailed(ctx, req)
	if err != nil {
		return "", err
	}
	return res.Token, nil
}

// SolveDetailed submits a widget job (Cloudflare Turnstile, reCAPTCHA v2/v3, hCaptcha)
// and returns the token plus any solver metadata (e.g. Turnstile UserAgent, TaskID).
func (s *TokenSolver) SolveDetailed(ctx context.Context, req TokenRequest) (TokenSolveResult, error) {
	if s == nil || strings.TrimSpace(s.APIKey) == "" {
		return TokenSolveResult{}, errors.New("captcha service API key is not configured (setting: captcha_api_key)")
	}
	kind := strings.ToLower(strings.TrimSpace(req.Type))
	method, ok := validTokenTypes[kind]
	if !ok {
		return TokenSolveResult{}, fmt.Errorf("unsupported captcha type %q (want turnstile, recaptcha_v2, recaptcha_v3, or hcaptcha)", req.Type)
	}
	if strings.TrimSpace(req.SiteKey) == "" || strings.TrimSpace(req.PageURL) == "" {
		return TokenSolveResult{}, errors.New("site_key and page_url are required")
	}
	if req.PollInterval <= 0 {
		req.PollInterval = 5 * time.Second
	}
	if req.MaxWait <= 0 {
		req.MaxWait = 180 * time.Second
	}

	if v2Base, ok := s.v2Endpoint(); ok {
		task := buildV2WidgetTask(kind, req)
		sol, taskID, err := s.solveV2Task(ctx, v2Base, task, req.PollInterval, req.MaxWait)
		if err == nil {
			tok := firstNonEmptyAnyStr(sol["token"], sol["gRecaptchaResponse"])
			ua, _ := sol["userAgent"].(string)
			return TokenSolveResult{Token: tok, UserAgent: ua, TaskID: taskID}, nil
		}
		if !strings.Contains(err.Error(), "status 404") {
			return TokenSolveResult{}, err
		}
	}

	params := url.Values{}
	params.Set("key", s.APIKey)
	params.Set("method", method)
	params.Set("json", "1")
	params.Set("sitekey", req.SiteKey)
	params.Set("pageurl", req.PageURL)
	if kind == "recaptcha_v3" {
		params.Set("version", "v3")
		if req.Action != "" {
			params.Set("action", req.Action)
		}
		if req.MinScore != "" {
			params.Set("min_score", req.MinScore)
		}
	}
	if kind == "turnstile" {
		if req.Action != "" {
			params.Set("action", req.Action)
		}
		if req.CData != "" {
			params.Set("data", req.CData)
		}
		if req.ChlPageData != "" {
			params.Set("pagedata", req.ChlPageData)
		}
	}
	if req.Enterprise {
		params.Set("enterprise", "1")
	}
	if req.DataS != "" {
		params.Set("data-s", req.DataS)
	}
	if req.Invisible {
		params.Set("invisible", "1")
	}
	if req.UserAgent != "" {
		params.Set("userAgent", req.UserAgent)
	}
	if req.Proxy != "" {
		applyV1ProxyParams(params, req)
	}

	tok, taskID, err := s.solveV1Job(ctx, params, req.PollInterval, req.MaxWait)
	if err != nil {
		return TokenSolveResult{}, err
	}
	return TokenSolveResult{Token: tok, TaskID: taskID}, nil
}

func buildV2WidgetTask(kind string, req TokenRequest) map[string]any {
	hasProxy := strings.TrimSpace(req.Proxy) != ""
	task := map[string]any{
		"websiteURL": req.PageURL,
		"websiteKey": req.SiteKey,
	}
	switch kind {
	case "turnstile":
		if hasProxy {
			task["type"] = "TurnstileTask"
		} else {
			task["type"] = "TurnstileTaskProxyless"
		}
		if req.Action != "" {
			task["action"] = req.Action
		}
		if req.CData != "" {
			task["data"] = req.CData
		}
		if req.ChlPageData != "" {
			task["pagedata"] = req.ChlPageData
		}
	case "recaptcha_v3":
		task["type"] = "RecaptchaV3TaskProxyless"
		if req.Action != "" {
			task["pageAction"] = req.Action
		}
		score := 0.5
		if req.MinScore != "" {
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(req.MinScore), 64); err == nil && parsed > 0 && parsed <= 1 {
				score = parsed
			}
		}
		task["minScore"] = score
		if req.Enterprise {
			task["isEnterprise"] = true
		}
		if req.APIDomain != "" {
			task["apiDomain"] = req.APIDomain
		}
	case "hcaptcha":
		if hasProxy {
			task["type"] = "HCaptchaTask"
		} else {
			task["type"] = "HCaptchaTaskProxyless"
		}
		if req.Invisible {
			task["isInvisible"] = true
		}
		if req.DataS != "" {
			task["enterprisePayload"] = map[string]any{"rqdata": req.DataS}
		}
	default: // recaptcha_v2
		if req.Enterprise {
			if hasProxy {
				task["type"] = "RecaptchaV2EnterpriseTask"
			} else {
				task["type"] = "RecaptchaV2EnterpriseTaskProxyless"
			}
			if req.DataS != "" {
				task["enterprisePayload"] = map[string]any{"s": req.DataS}
			}
		} else {
			if hasProxy {
				task["type"] = "RecaptchaV2Task"
			} else {
				task["type"] = "RecaptchaV2TaskProxyless"
			}
			if req.DataS != "" {
				task["recaptchaDataSValue"] = req.DataS
			}
		}
		if req.Invisible {
			task["isInvisible"] = true
		}
		if req.APIDomain != "" {
			task["apiDomain"] = req.APIDomain
		}
	}
	if req.UserAgent != "" {
		task["userAgent"] = req.UserAgent
	}
	if hasProxy && kind != "recaptcha_v3" {
		applyV2ProxyFields(task, req)
	}
	return task
}

func applyV2ProxyFields(task map[string]any, req TokenRequest) {
	raw := strings.TrimSpace(req.Proxy)
	if !strings.Contains(raw, "://") {
		raw = strings.ToLower(firstNonEmptyStr(req.ProxyType, "http")) + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "socks5", "socks5h":
		task["proxyType"] = "socks5"
	case "socks4":
		task["proxyType"] = "socks4"
	case "https":
		task["proxyType"] = "https"
	default:
		task["proxyType"] = "http"
	}
	task["proxyAddress"] = u.Hostname()
	if port, err := strconv.Atoi(u.Port()); err == nil && port > 0 {
		task["proxyPort"] = port
	}
	login := req.ProxyLogin
	pass := req.ProxyPasswd
	if u.User != nil {
		if login == "" {
			login = u.User.Username()
		}
		if pw, ok := u.User.Password(); ok && pass == "" {
			pass = pw
		}
	}
	if login != "" {
		task["proxyLogin"] = login
	}
	if pass != "" {
		task["proxyPassword"] = pass
	}
}

func applyV1ProxyParams(params url.Values, req TokenRequest) {
	raw := strings.TrimSpace(req.Proxy)
	pType := strings.ToUpper(firstNonEmptyStr(req.ProxyType, "HTTP"))
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			switch strings.ToLower(u.Scheme) {
			case "socks5", "socks5h":
				pType = "SOCKS5"
			case "socks4":
				pType = "SOCKS4"
			case "https":
				pType = "HTTPS"
			default:
				pType = "HTTP"
			}
			if u.User != nil {
				raw = u.User.String() + "@" + u.Host
			} else {
				raw = u.Host
			}
		}
	}
	params.Set("proxy", raw)
	params.Set("proxytype", pType)
	if req.ProxyLogin != "" || req.ProxyPasswd != "" {
		params.Set("proxylogin", req.ProxyLogin)
		params.Set("proxypassword", req.ProxyPasswd)
	}
}

func (s *TokenSolver) solveV2Task(ctx context.Context, v2Base string, task map[string]any, pollInterval, maxWait time.Duration) (map[string]any, string, error) {
	createBody, _ := json.Marshal(map[string]any{
		"clientKey": s.APIKey,
		"task":      task,
	})
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	data, status, err := s.postJSON(cctx, v2Base+"/createTask", createBody)
	cancel()
	if err != nil {
		return nil, "", err
	}
	if status == http.StatusNotFound {
		return nil, "", fmt.Errorf("createTask status 404")
	}
	var createResp struct {
		ErrorID          int             `json:"errorId"`
		ErrorCode        string          `json:"errorCode"`
		ErrorDescription string          `json:"errorDescription"`
		TaskID           json.RawMessage `json:"taskId"`
	}
	if err := json.Unmarshal(data, &createResp); err != nil {
		return nil, "", fmt.Errorf("parse 2Captcha createTask response: %w", err)
	}
	if createResp.ErrorID != 0 {
		return nil, "", fmt.Errorf("2Captcha createTask failed: %s (%s)", createResp.ErrorCode, createResp.ErrorDescription)
	}
	taskIDStr := strings.Trim(string(createResp.TaskID), `" `)
	if taskIDStr == "" || taskIDStr == "null" {
		return nil, "", errors.New("2Captcha createTask returned empty taskId")
	}

	var taskIDVal any = createResp.TaskID
	deadline := time.Now().Add(maxWait)
	pollBody, _ := json.Marshal(map[string]any{
		"clientKey": s.APIKey,
		"taskId":    taskIDVal,
	})
	for {
		if !sleepCtx(ctx, pollInterval) {
			return nil, taskIDStr, ctx.Err()
		}
		if time.Now().After(deadline) {
			return nil, taskIDStr, fmt.Errorf("2Captcha solve timed out after %s (taskId=%s)", maxWait, taskIDStr)
		}
		pctx, pcancel := context.WithTimeout(ctx, 30*time.Second)
		rdata, _, perr := s.postJSON(pctx, v2Base+"/getTaskResult", pollBody)
		pcancel()
		if perr != nil {
			continue
		}
		var res struct {
			ErrorID          int            `json:"errorId"`
			ErrorCode        string         `json:"errorCode"`
			ErrorDescription string         `json:"errorDescription"`
			Status           string         `json:"status"`
			Solution         map[string]any `json:"solution"`
		}
		if json.Unmarshal(rdata, &res) != nil {
			continue
		}
		if res.ErrorID != 0 {
			return nil, taskIDStr, fmt.Errorf("2Captcha solve failed: %s (%s)", res.ErrorCode, res.ErrorDescription)
		}
		if strings.EqualFold(res.Status, "ready") {
			return res.Solution, taskIDStr, nil
		}
	}
}

func (s *TokenSolver) solveV1Job(ctx context.Context, params url.Values, pollInterval, maxWait time.Duration) (string, string, error) {
	base := s.v1Endpoint()
	var jobID string
	{
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		data, err := s.postForm(cctx, base+"/in.php", params)
		cancel()
		if err != nil {
			return "", "", err
		}
		var in struct {
			Status  int    `json:"status"`
			Request string `json:"request"`
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return "", "", fmt.Errorf("submit captcha job: %w", err)
		}
		if in.Status != 1 {
			return "", "", fmt.Errorf("captcha submit failed: %s", in.Request)
		}
		jobID = in.Request
	}

	deadline := time.Now().Add(maxWait)
	get := url.Values{}
	get.Set("key", s.APIKey)
	get.Set("action", "get")
	get.Set("json", "1")
	get.Set("id", jobID)
	for {
		if !sleepCtx(ctx, pollInterval) {
			return "", jobID, ctx.Err()
		}
		if time.Now().After(deadline) {
			return "", jobID, fmt.Errorf("captcha solve timed out after %s", maxWait)
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		data, err := s.postForm(cctx, base+"/res.php", get)
		cancel()
		if err != nil {
			continue
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
			return out.Request, jobID, nil
		case strings.EqualFold(out.Request, "CAPCHA_NOT_READY"):
			continue
		default:
			return "", jobID, fmt.Errorf("captcha solve failed: %s", out.Request)
		}
	}
}

func (s *TokenSolver) postJSON(ctx context.Context, endpoint string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return data, resp.StatusCode, err
}

func (s *TokenSolver) postForm(ctx context.Context, endpoint string, params url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
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

func firstNonEmptyAnyStr(vals ...any) string {
	for _, v := range vals {
		if str, ok := v.(string); ok && strings.TrimSpace(str) != "" {
			return str
		}
	}
	return ""
}
