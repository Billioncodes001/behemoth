package captcha

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Form solving: fetch the page, discover the captcha <img> + hash field + all
// hidden inputs, OCR a FRESH challenge every attempt and submit, judging success
// by configurable markers. One tool call replaces the multi-hundred-turn
// "fetch ASCII art and guess" loop that burns millions of tokens.

// defaultFailureMarkers cover the common captcha rejection phrasings (case-
// insensitive substring match).
var defaultFailureMarkers = []string{
	"invalid captcha", "captcha is invalid", "incorrect captcha",
	"wrong captcha", "captcha does not match", "captcha is incorrect",
	"invalid capcha", "captcha error", "captcha was invalid",
	"验证码错误", "验证码不正确",
}

// defaultRejectMarkers are NON-captcha form rejections (duplicate email,
// taken username, ...). When one appears the loop must stop instead of
// burning its remaining attempts on a permanently invalid submission.
var defaultRejectMarkers = []string{
	"already registered", "email already", "username already",
	"already exists", "already taken", "already in use",
	"已存在", "已被注册",
}

// FormSolveRequest describes the captcha-protected form to defeat.
type FormSolveRequest struct {
	// PageURL is fetched (fresh) before every attempt to get a new challenge.
	PageURL string
	// FormAction overrides the discovered form action ("" = auto-discover).
	FormAction string
	// Method overrides the form method ("" = discovered, default POST).
	Method string
	// CaptchaImageURL overrides the discovered captcha image URL.
	CaptchaImageURL string
	// CaptchaField is the answer input name ("" = auto-discover).
	CaptchaField string
	// CaptchaHashField is the hidden key input name (e.g. django's captcha_0).
	CaptchaHashField string
	// ExtraFields are posted alongside the discovered hidden inputs.
	ExtraFields map[string]string
	// SuccessMarkers / FailureMarkers are case-insensitive body substrings.
	SuccessMarkers []string
	FailureMarkers []string
	// RejectMarkers are NON-captcha rejections (e.g. "email already
	// registered") that stop the loop immediately instead of retrying.
	// Empty uses defaultRejectMarkers; pass a single "-" to disable.
	RejectMarkers []string
	// MaxAttempts caps the fetch→OCR→submit loop (default 25, max 200).
	MaxAttempts int
	// Delay between attempts (default 1s) to stay polite.
	Delay time.Duration
	// Timeout bounds the whole run (default 5m, max 15m).
	Timeout time.Duration
	// UserAgent for every request.
	UserAgent string
	// ProxyURL optionally routes all requests through a proxy.
	ProxyURL string
	// VerifyTLS disables the default InsecureSkipVerify (pentest targets often
	// have broken chains).
	VerifyTLS bool
	// OCR passes tuning through to SolveImageCaptcha.
	OCR OCRRequest
	// Recognizer overrides OCR (tests / alternative engines).
	Recognizer Recognizer
}

// FormAttempt is one loop iteration's outcome.
type FormAttempt struct {
	Attempt int    `json:"attempt"`
	Answer  string `json:"answer"`
	Status  int    `json:"status"`
	Outcome string `json:"outcome"` // solved | wrong | error
	Detail  string `json:"detail,omitempty"`
}

// FormSolveResult is the aggregate outcome.
type FormSolveResult struct {
	Solved      bool          `json:"solved"`
	Answer      string        `json:"answer,omitempty"`
	Attempts    []FormAttempt `json:"attempts"`
	FinalStatus int           `json:"final_status"`
	FinalURL    string        `json:"final_url,omitempty"`
	Evidence    string        `json:"evidence,omitempty"`
	ElapsedMS   int64         `json:"elapsed_ms"`
	Error       string        `json:"error,omitempty"`
}

var (
	reFormTag     = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	reAttr        = regexp.MustCompile(`(?i)([a-zA-Z-]+)\s*=\s*"([^"]*)"`)
	reInputTag    = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	reImgTag      = regexp.MustCompile(`(?is)<img\b[^>]*>`)
	reTextareaTag = regexp.MustCompile(`(?is)<textarea\b[^>]*>`)
	// captchaInputNameRe matches input/textarea tags whose name contains
	// "captcha" (captcha_1, captcha_hash, txtCaptcha, ...) — used to detect
	// that a re-rendered page still expects a captcha answer.
	captchaInputNameRe = regexp.MustCompile(`(?is)<(?:input|textarea)\b[^>]*\bname\s*=\s*"?[^">\s]*captcha[^">\s]*"?[^>]*>`)
)

// parsedForm is everything the loop needs from the page HTML.
type parsedForm struct {
	Action       string
	Method       string
	Hidden       map[string]string
	AllNames     []string // every input name in the form (hidden or visible)
	CaptchaImg   string
	CaptchaHash  string
	CaptchaField string
}

// captchaImageSrcs returns img srcs that look like captcha challenges.
func captchaImageSrcs(segment string) []string {
	var out []string
	for _, m := range reImgTag.FindAllString(segment, -1) {
		for _, attr := range reAttr.FindAllStringSubmatch(m, -1) {
			if strings.EqualFold(attr[1], "src") && strings.Contains(strings.ToLower(attr[2]), "captcha") {
				out = append(out, attr[2])
			}
		}
	}
	return out
}

// firstOf returns the first entry or "".
func firstOf(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

// collectInputs gathers hidden/textarea field defaults into the map.
func collectInputs(segment string, into map[string]string) {
	collect := func(m string) {
		var name, value string
		for _, attr := range reAttr.FindAllStringSubmatch(m, -1) {
			switch strings.ToLower(attr[1]) {
			case "name":
				name = attr[2]
			case "value":
				value = attr[2]
			}
		}
		if name != "" {
			if _, exists := into[name]; !exists {
				into[name] = value
			}
		}
	}
	for _, m := range reInputTag.FindAllString(segment, -1) {
		lower := strings.ToLower(m)
		isHidden := strings.Contains(lower, `type="hidden"`) ||
			strings.Contains(lower, "type='hidden'") ||
			!strings.Contains(lower, "type=")
		if isHidden {
			collect(m)
		}
	}
	for _, m := range reTextareaTag.FindAllString(segment, -1) {
		collect(m)
	}
}

// collectAllNames gathers every input name (hidden or visible) so captcha
// answer fields like <input type="text" name="captcha_1"> can be discovered.
func collectAllNames(segment string, into *[]string) {
	for _, m := range reInputTag.FindAllString(segment, -1) {
		for _, attr := range reAttr.FindAllStringSubmatch(m, -1) {
			if strings.EqualFold(attr[1], "name") && strings.TrimSpace(attr[2]) != "" {
				*into = append(*into, attr[2])
			}
		}
	}
}

// parseCaptchaForm extracts the first form containing a captcha-looking image
// (falling back to the first form on the page).
func parseCaptchaForm(body string) parsedForm {
	pf := parsedForm{Hidden: map[string]string{}, Method: "POST"}
	forms := reFormTag.FindAllStringIndex(body, -1)
	for i, loc := range forms {
		end := len(body)
		if i+1 < len(forms) {
			end = forms[i+1][0]
		}
		segment := body[loc[1]:end]
		if endIdx := strings.Index(strings.ToLower(segment), "</form>"); endIdx >= 0 {
			segment = segment[:endIdx]
		}
		imgs := captchaImageSrcs(segment)
		if len(imgs) == 0 {
			continue
		}
		pf.CaptchaImg = imgs[0]
		parseFormTagAttrs(body[loc[0]:loc[1]], &pf)
		collectInputs(segment, pf.Hidden)
		collectAllNames(segment, &pf.AllNames)
		break
	}
	if pf.CaptchaImg == "" && len(forms) > 0 {
		loc := forms[0]
		segment := body[loc[1]:]
		if endIdx := strings.Index(strings.ToLower(segment), "</form>"); endIdx >= 0 {
			segment = segment[:endIdx]
		}
		pf.CaptchaImg = firstOf(captchaImageSrcs(segment))
		parseFormTagAttrs(body[loc[0]:loc[1]], &pf)
		collectInputs(segment, pf.Hidden)
		collectAllNames(segment, &pf.AllNames)
	}
	return pf
}

func parseFormTagAttrs(tag string, pf *parsedForm) {
	for _, attr := range reAttr.FindAllStringSubmatch(tag, -1) {
		switch strings.ToLower(attr[1]) {
		case "action":
			pf.Action = attr[2]
		case "method":
			pf.Method = strings.ToUpper(attr[2])
		}
	}
}

// discoverCaptchaField picks the answer field + hidden key from the parsed form.
// It searches every input name (visible ones included) for captcha-ish names and
// prefers the numeric-suffixed answer input (captcha_1) over the key (captcha_0).
func discoverCaptchaField(pf *parsedForm, explicitField, explicitHash string) (field, hash string) {
	if explicitField != "" {
		return explicitField, explicitHash
	}
	seen := map[string]bool{}
	var candidates []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		if strings.Contains(strings.ToLower(name), "captcha") {
			candidates = append(candidates, name)
		}
	}
	for _, name := range pf.AllNames {
		add(name)
	}
	for name := range pf.Hidden {
		add(name)
	}
	var answer, key string
	for _, name := range candidates {
		lower := strings.ToLower(name)
		if strings.HasSuffix(name, "_0") || strings.HasSuffix(lower, "key") ||
			strings.Contains(lower, "hash") || strings.HasSuffix(lower, "id") {
			if key == "" {
				key = name
			}
			continue
		}
		if answer == "" {
			answer = name
		}
	}
	if answer == "" && key != "" {
		answer, key = key, ""
	}
	return answer, key
}

// resolveReference resolves a possibly-relative URL against the page URL.
func resolveReference(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	if base != nil {
		return base.ResolveReference(r).String()
	}
	return ref
}

// NewFormClient builds a cookie-jar client honoring the optional proxy.
func NewFormClient(timeout time.Duration, proxyURL string, verifyTLS bool) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS},
	}
	if proxyURL != "" {
		pu, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy url: %w", err)
		}
		transport.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{
		Timeout:   timeout,
		Jar:       jar,
		Transport: transport,
	}, nil
}

// containsFold reports whether any marker appears in the body.
func containsFold(body string, markers []string) (string, bool) {
	lower := strings.ToLower(body)
	for _, m := range markers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return m, true
		}
	}
	return "", false
}

// hasCaptchaInput reports whether the body still renders a captcha form:
// either a captcha image or a captcha-named input field (answer or hash —
// Django error pages re-render both).
func hasCaptchaInput(body string) bool {
	if len(captchaImageSrcs(body)) > 0 {
		return true
	}
	return strings.Contains(strings.ToLower(body), "captcha_") ||
		captchaInputNameRe.MatchString(body)
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// SolveForm drives the complete captcha loop: fetch → discover → OCR → submit →
// judge → retry, until a success marker (or a non-captcha rejection) appears.
func SolveForm(ctx context.Context, req FormSolveRequest) (FormSolveResult, error) {
	start := time.Now()
	var res FormSolveResult
	if strings.TrimSpace(req.PageURL) == "" {
		return res, fmt.Errorf("page_url is required")
	}
	if req.MaxAttempts <= 0 {
		req.MaxAttempts = 25
	}
	if req.MaxAttempts > 200 {
		req.MaxAttempts = 200
	}
	if req.Timeout <= 0 {
		req.Timeout = 5 * time.Minute
	}
	if req.Timeout > 15*time.Minute {
		req.Timeout = 15 * time.Minute
	}
	if req.Delay <= 0 {
		req.Delay = time.Second
	}
	if req.UserAgent == "" {
		req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	}

	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	client, err := NewFormClient(60*time.Second, req.ProxyURL, req.VerifyTLS)
	if err != nil {
		return res, err
	}

	recognizer := req.Recognizer
	if recognizer == nil {
		recognizer = func(ctx context.Context, img []byte) ([]string, error) {
			r, err := SolveImageCaptcha(ctx, img, req.OCR)
			if err != nil {
				return nil, err
			}
			return r.Candidates, nil
		}
	}

	pageURL := req.PageURL
	for attempt := 1; attempt <= req.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			res.Error = "timeout: " + err.Error()
			break
		}
		page, status, err := httpGet(ctx, client, pageURL, req.UserAgent)
		if err != nil {
			res.Attempts = append(res.Attempts, FormAttempt{Attempt: attempt, Outcome: "error", Detail: "fetch page: " + err.Error()})
			res.Error = err.Error()
			break
		}
		res.FinalStatus = status
		base, _ := url.Parse(pageURL)
		pf := parseCaptchaForm(page)
		field, hashField := discoverCaptchaField(&pf, req.CaptchaField, req.CaptchaHashField)
		if field == "" {
			res.Error = "no captcha input found on page"
			break
		}
		imgRef := firstNonEmptyStr(req.CaptchaImageURL, pf.CaptchaImg)
		if imgRef == "" {
			res.Error = "no captcha image found on page"
			break
		}
		imgBytes, _, err := httpGetBytes(ctx, client, resolveReference(base, imgRef), req.UserAgent)
		if err != nil {
			res.Attempts = append(res.Attempts, FormAttempt{Attempt: attempt, Outcome: "error", Detail: "fetch captcha image: " + err.Error()})
			res.Error = err.Error()
			break
		}
		candidates, err := recognizer(ctx, imgBytes)
		if err != nil || len(candidates) == 0 {
			detail := "ocr produced no candidates"
			if err != nil {
				detail = "ocr: " + err.Error()
			}
			res.Attempts = append(res.Attempts, FormAttempt{Attempt: attempt, Outcome: "error", Detail: detail})
			res.Error = detail
			if !sleepCtx(ctx, req.Delay) {
				res.Error = "timeout"
			}
			continue
		}

		answer := candidates[0]
		postURL := resolveReference(base, firstNonEmptyStr(req.FormAction, pf.Action, pageURL))
		form := url.Values{}
		for k, v := range pf.Hidden {
			form.Set(k, v)
		}
		for k, v := range req.ExtraFields {
			form.Set(k, v)
		}
		form.Set(field, answer)
		if hashField != "" && pf.Hidden[hashField] != "" {
			form.Set(hashField, pf.Hidden[hashField])
		}

		method := strings.ToUpper(firstNonEmptyStr(req.Method, pf.Method, "POST"))
		respBody, respStatus, respURL, err := httpDo(ctx, client, method, postURL, form, req.UserAgent, pageURL)
		if err != nil {
			res.Attempts = append(res.Attempts, FormAttempt{Attempt: attempt, Answer: answer, Outcome: "error", Detail: err.Error()})
			res.Error = err.Error()
			break
		}
		res.FinalStatus = respStatus
		res.FinalURL = respURL

		if m, ok := containsFold(respBody, req.SuccessMarkers); ok {
			res.Solved = true
			res.Answer = answer
			res.Evidence = fmt.Sprintf("success marker %q found (HTTP %d)", m, respStatus)
			res.Attempts = append(res.Attempts, FormAttempt{Attempt: attempt, Answer: answer, Status: respStatus, Outcome: "solved"})
			break
		}
		rejects := req.RejectMarkers
		if len(rejects) == 0 {
			rejects = defaultRejectMarkers
		}
		if len(rejects) == 1 && rejects[0] == "-" {
			rejects = nil
		}
		if m, ok := containsFold(respBody, rejects); ok {
			// Non-captcha rejection (duplicate email, taken username, ...):
			// retrying with fresh challenges can never fix this — stop.
			res.Evidence = fmt.Sprintf("rejection marker %q found (HTTP %d)", m, respStatus)
			res.Error = "rejected: " + m
			res.Attempts = append(res.Attempts, FormAttempt{Attempt: attempt, Answer: answer, Status: respStatus, Outcome: "rejected", Detail: "marker: " + m})
			break
		}
		failures := req.FailureMarkers
		if len(failures) == 0 {
			failures = defaultFailureMarkers
		}
		if m, ok := containsFold(respBody, failures); ok {
			res.Attempts = append(res.Attempts, FormAttempt{Attempt: attempt, Answer: answer, Status: respStatus, Outcome: "wrong", Detail: "marker: " + m})
		} else if respStatus >= 200 && respStatus < 400 && !hasCaptchaInput(respBody) {
			res.Solved = true
			res.Answer = answer
			res.Evidence = fmt.Sprintf("response no longer contains a captcha form (HTTP %d)", respStatus)
			res.Attempts = append(res.Attempts, FormAttempt{Attempt: attempt, Answer: answer, Status: respStatus, Outcome: "solved"})
			break
		} else {
			res.Attempts = append(res.Attempts, FormAttempt{Attempt: attempt, Answer: answer, Status: respStatus, Outcome: "wrong", Detail: "captcha form still present"})
		}
		if !sleepCtx(ctx, req.Delay) {
			res.Error = "timeout"
			break
		}
	}

	res.ElapsedMS = time.Since(start).Milliseconds()
	if !res.Solved && res.Error == "" && len(res.Attempts) > 0 {
		res.Error = fmt.Sprintf("captcha not solved after %d attempts", len(res.Attempts))
	}
	return res, nil
}

// sleepCtx waits for d or until ctx is done; returns false on ctx completion.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// httpGet fetches a URL with the shared client and returns the body.
func httpGet(ctx context.Context, client *http.Client, rawURL, ua string) (string, int, error) {
	body, status, err := httpGetBytes(ctx, client, rawURL, ua)
	return string(body), status, err
}

// httpGetBytes fetches a URL and returns raw bytes (binary-safe: captcha PNGs).
func httpGetBytes(ctx context.Context, client *http.Client, rawURL, ua string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// httpDo submits the form (cookies ride the shared jar) and returns the final
// body, status and URL.
func httpDo(ctx context.Context, client *http.Client, method, rawURL string, form url.Values, ua, referer string) (string, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if referer != "" {
		req.Header.Set("Referer", referer)
		req.Header.Set("Origin", originOf(rawURL))
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", resp.StatusCode, "", err
	}
	return string(data), resp.StatusCode, resp.Request.URL.String(), nil
}

func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return u.String()
}
