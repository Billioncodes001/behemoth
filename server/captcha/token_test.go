package captcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenSolverV2AllModesAndBalance(t *testing.T) {
	var lastTask map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/getBalance":
			var body struct {
				ClientKey string `json:"clientKey"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.ClientKey != "valid-2captcha-key" {
				_, _ = w.Write([]byte(`{"errorId":1,"errorCode":"ERROR_KEY_DOES_NOT_EXIST","errorDescription":"Account not found"}`))
				return
			}
			_, _ = w.Write([]byte(`{"errorId":0,"balance":14.75}`))
		case "/createTask":
			var body struct {
				ClientKey string         `json:"clientKey"`
				Task      map[string]any `json:"task"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastTask = body.Task
			_, _ = w.Write([]byte(`{"errorId":0,"taskId":987654}`))
		case "/getTaskResult":
			taskType, _ := lastTask["type"].(string)
			switch taskType {
			case "ImageToTextTask":
				_, _ = w.Write([]byte(`{"errorId":0,"status":"ready","solution":{"text":"X7K9M"}}`))
			case "TurnstileTaskProxyless":
				_, _ = w.Write([]byte(`{"errorId":0,"status":"ready","solution":{"token":"0.cf-turnstile-tok","userAgent":"Mozilla/5.0 CF"}}`))
			case "RecaptchaV3TaskProxyless":
				_, _ = w.Write([]byte(`{"errorId":0,"status":"ready","solution":{"gRecaptchaResponse":"v3-score-token"}}`))
			default:
				_, _ = w.Write([]byte(`{"errorId":0,"status":"ready","solution":{"gRecaptchaResponse":"v2-token"}}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Point BaseURL to mock v2 endpoint by including api.2captcha.com query/override via custom v2 check:
	// let's test both explicit v1 fallback and v2 endpoint routing by rewriting transport URL.
	origTransport := http.DefaultTransport
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			clone := req.Clone(req.Context())
			clone.URL.Scheme = "http"
			clone.URL.Host = srv.Listener.Addr().String()
			return origTransport.RoundTrip(clone)
		}),
	}

	solver := NewTokenSolver("valid-2captcha-key", "https://api.2captcha.com", client)

	bal, err := solver.CheckBalance(context.Background())
	if err != nil || bal != 14.75 {
		t.Fatalf("CheckBalance got (%v, %v), want (14.75, nil)", bal, err)
	}

	badSolver := NewTokenSolver("wrong-key", "https://api.2captcha.com", client)
	if _, err := badSolver.CheckBalance(context.Background()); err == nil {
		t.Fatal("expected error for invalid 2Captcha API key")
	}

	// 1. Image CAPTCHA
	imgRes, err := solver.SolveImage(context.Background(), ImageSolveRequest{
		ImageBytes:    []byte("fake-png-bytes"),
		CaseSensitive: true,
		Math:          false,
		PollInterval:  10 * time.Millisecond,
	})
	if err != nil || imgRes.Text != "X7K9M" {
		t.Fatalf("SolveImage got (%+v, %v)", imgRes, err)
	}
	if lastTask["type"] != "ImageToTextTask" || lastTask["case"] != true {
		t.Fatalf("unexpected ImageToTextTask payload: %+v", lastTask)
	}

	// 2. Cloudflare Turnstile + Challenge data
	cfRes, err := solver.SolveDetailed(context.Background(), TokenRequest{
		Type:         "turnstile",
		SiteKey:      "0x4AAAAAAAB",
		PageURL:      "https://target.example.com/login",
		Action:       "managed",
		CData:        "cdata-123",
		ChlPageData:  "pagedata-456",
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil || cfRes.Token != "0.cf-turnstile-tok" || cfRes.UserAgent != "Mozilla/5.0 CF" {
		t.Fatalf("Turnstile SolveDetailed got (%+v, %v)", cfRes, err)
	}
	if lastTask["type"] != "TurnstileTaskProxyless" || lastTask["data"] != "cdata-123" || lastTask["pagedata"] != "pagedata-456" {
		t.Fatalf("unexpected Turnstile payload: %+v", lastTask)
	}

	// 3. reCAPTCHA v3
	v3Res, err := solver.SolveDetailed(context.Background(), TokenRequest{
		Type:         "recaptcha_v3",
		SiteKey:      "6Lc_v3",
		PageURL:      "https://target.example.com/api",
		Action:       "submit_login",
		MinScore:     "0.7",
		Enterprise:   true,
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil || v3Res.Token != "v3-score-token" {
		t.Fatalf("reCAPTCHA v3 got (%+v, %v)", v3Res, err)
	}
	if lastTask["type"] != "RecaptchaV3TaskProxyless" || lastTask["pageAction"] != "submit_login" || lastTask["minScore"] != 0.7 || lastTask["isEnterprise"] != true {
		t.Fatalf("unexpected reCAPTCHA v3 payload: %+v", lastTask)
	}

	// 4. reCAPTCHA v2 Invisible
	v2Tok, err := solver.Solve(context.Background(), TokenRequest{
		Type:         "recaptcha_v2",
		SiteKey:      "6Lc_v2",
		PageURL:      "https://target.example.com/form",
		Invisible:    true,
		DataS:        "datas-xyz",
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil || v2Tok != "v2-token" {
		t.Fatalf("reCAPTCHA v2 got (%q, %v)", v2Tok, err)
	}
	if lastTask["type"] != "RecaptchaV2TaskProxyless" || lastTask["isInvisible"] != true || lastTask["recaptchaDataSValue"] != "datas-xyz" {
		t.Fatalf("unexpected reCAPTCHA v2 payload: %+v", lastTask)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
