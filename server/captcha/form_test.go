package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeCaptchaSite stands in for a Django-style captcha form: CSRF cookie +
// hidden token, captcha image, hash field, and a fixed expected answer.
func fakeCaptchaSite(t *testing.T, answer string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form: %v", err)
			}
			if ck, err := r.Cookie("sid"); err != nil || ck.Value != "sess-1" {
				t.Logf("missing session cookie: %v", err)
			}
			if r.PostFormValue("csrfmiddlewaretoken") != "tok-1" {
				t.Logf("missing csrf token")
			}
			if r.PostFormValue("captcha_0") != "h1" {
				t.Logf("missing captcha hash")
			}
			if r.PostFormValue("captcha_1") == answer {
				w.Header().Set("Location", "/welcome")
				w.WriteHeader(http.StatusFound)
				_, _ = w.Write([]byte("redirecting"))
				return
			}
			_, _ = w.Write([]byte(`<html><ul class="errorlist"><li>Invalid CAPTCHA</li></ul>
<form action="/signup" method="post"><input type="hidden" name="csrfmiddlewaretoken" value="tok-1">
<input type="hidden" name="captcha_0" value="h2"><input name="captcha_1"></form></html>`))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "sess-1"})
		_, _ = w.Write([]byte(`<html><form action="/signup" method="post">
<input type="hidden" name="csrfmiddlewaretoken" value="tok-1">
<input type="hidden" name="captcha_0" value="h1">
<img src="/captcha/image.png" alt="captcha"><input name="captcha_1"></form></html>`))
	})
	mux.HandleFunc("/captcha/image.png", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("PNGDATA"))
	})
	mux.HandleFunc("/welcome", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Welcome, registration complete"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestSolveFormRetriesWithFreshChallenges drives the loop with an injected
// recognizer that answers wrong twice, then correctly — proving the loop
// fetches fresh challenges, keeps the session and stops on success.
func TestSolveFormRetriesWithFreshChallenges(t *testing.T) {
	srv := fakeCaptchaSite(t, "a2b9")
	calls := 0
	res, err := SolveForm(context.Background(), FormSolveRequest{
		PageURL:        srv.URL + "/signup",
		MaxAttempts:    10,
		Delay:          time.Millisecond,
		Timeout:        10 * time.Second,
		SuccessMarkers: []string{"registration complete"},
		Recognizer: func(ctx context.Context, img []byte) ([]string, error) {
			calls++
			if string(img) != "PNGDATA" {
				t.Errorf("unexpected captcha payload %q", img)
			}
			if calls < 3 {
				return []string{"zzzz"}, nil
			}
			return []string{"a2b9", "zzzz"}, nil
		},
	})
	if err != nil {
		t.Fatalf("SolveForm: %v", err)
	}
	if !res.Solved {
		t.Fatalf("expected solved, got %+v", res)
	}
	if res.Answer != "a2b9" {
		t.Fatalf("expected answer a2b9, got %q", res.Answer)
	}
	if calls != 3 {
		t.Fatalf("expected 3 OCR calls, got %d", calls)
	}
	if !strings.Contains(res.Evidence, "registration complete") {
		t.Fatalf("evidence should carry the success marker: %q", res.Evidence)
	}
}

// TestSolveFormGivesUpAfterMaxAttempts verifies the not-solved path.
func TestSolveFormGivesUpAfterMaxAttempts(t *testing.T) {
	srv := fakeCaptchaSite(t, "a2b9")
	res, err := SolveForm(context.Background(), FormSolveRequest{
		PageURL:        srv.URL + "/signup",
		MaxAttempts:    4,
		Delay:          time.Millisecond,
		Timeout:        10 * time.Second,
		FailureMarkers: []string{"Invalid CAPTCHA"},
		Recognizer: func(ctx context.Context, img []byte) ([]string, error) {
			return []string{"wrong"}, nil
		},
	})
	if err != nil {
		t.Fatalf("SolveForm: %v", err)
	}
	if res.Solved {
		t.Fatal("expected failure")
	}
	if len(res.Attempts) != 4 {
		t.Fatalf("expected 4 attempts, got %d", len(res.Attempts))
	}
	if !strings.Contains(res.Error, "not solved") {
		t.Fatalf("expected not-solved error, got %q", res.Error)
	}
	for _, a := range res.Attempts {
		if a.Outcome != "wrong" {
			t.Fatalf("attempt %d outcome = %q, want wrong", a.Attempt, a.Outcome)
		}
	}
}

// TestSolveFormStopsOnNonCaptchaRejection: a permanent form error (duplicate
// email, taken username) must end the loop after ONE attempt — retrying with
// fresh captcha challenges can never fix it (learned from the OSPOLY signup
// run, where the success/failure page carried Django errorlist entries).
func TestSolveFormStopsOnNonCaptchaRejection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`<html><ul class="errorlist"><li>Email already registered</li></ul>
<form action="/signup" method="post"><input type="hidden" name="csrfmiddlewaretoken" value="tok-1">
<input type="hidden" name="captcha_0" value="h2"><input name="captcha_1"></form></html>`))
			return
		}
		_, _ = w.Write([]byte(`<html><form action="/signup" method="post">
<input type="hidden" name="csrfmiddlewaretoken" value="tok-1">
<input type="hidden" name="captcha_0" value="h1">
<img src="/captcha/image.png" alt="captcha"><input name="captcha_1"></form></html>`))
	})
	mux.HandleFunc("/captcha/image.png", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("PNGDATA"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rec := func(ctx context.Context, img []byte) ([]string, error) { return []string{"a2b9"}, nil }

	res, err := SolveForm(context.Background(), FormSolveRequest{
		PageURL:     srv.URL + "/signup",
		MaxAttempts: 10,
		Delay:       time.Millisecond,
		Timeout:     10 * time.Second,
		Recognizer:  rec,
	})
	if err != nil {
		t.Fatalf("SolveForm: %v", err)
	}
	if res.Solved {
		t.Fatalf("expected rejection, got solved: %+v", res)
	}
	if len(res.Attempts) != 1 {
		t.Fatalf("expected the loop to stop after 1 attempt, got %d", len(res.Attempts))
	}
	if res.Attempts[0].Outcome != "rejected" {
		t.Fatalf("outcome = %q, want rejected", res.Attempts[0].Outcome)
	}
	if !strings.Contains(res.Error, "rejected") {
		t.Fatalf("error should explain the rejection, got %q", res.Error)
	}

	// RejectMarkers ["-"] disables the stop condition: the loop burns its
	// full attempt budget like before.
	res2, err := SolveForm(context.Background(), FormSolveRequest{
		PageURL:       srv.URL + "/signup",
		MaxAttempts:   3,
		Delay:         time.Millisecond,
		Timeout:       10 * time.Second,
		RejectMarkers: []string{"-"},
		Recognizer:    rec,
	})
	if err != nil {
		t.Fatalf("SolveForm(disabled): %v", err)
	}
	if len(res2.Attempts) != 3 {
		t.Fatalf("expected 3 attempts with reject markers disabled, got %d", len(res2.Attempts))
	}
	for _, a := range res2.Attempts {
		if a.Outcome != "wrong" {
			t.Fatalf("attempt %d outcome = %q, want wrong", a.Attempt, a.Outcome)
		}
	}
}

// TestParseCaptchaFormDiscovery checks auto-discovery of the image, fields and
// hidden inputs from typical markup.
func TestParseCaptchaFormDiscovery(t *testing.T) {
	pf := parseCaptchaForm(`<html><form action="/submit" method="post">
<input type="hidden" name="csrfmiddlewaretoken" value="abc">
<input type="hidden" name="captcha_0" value="h1">
<img src="/captcha/foo.png" alt="captcha">
<input type="text" name="captcha_1" id="id_captcha_1" autocomplete="off">
</form></html>`)
	if pf.CaptchaImg != "/captcha/foo.png" {
		t.Fatalf("captcha image not discovered: %q", pf.CaptchaImg)
	}
	if pf.Action != "/submit" || pf.Method != "POST" {
		t.Fatalf("action/method wrong: %q %q", pf.Action, pf.Method)
	}
	if pf.Hidden["csrfmiddlewaretoken"] != "abc" || pf.Hidden["captcha_0"] != "h1" {
		t.Fatalf("hidden inputs not collected: %+v", pf.Hidden)
	}
	field, hash := discoverCaptchaField(&pf, "", "")
	if field != "captcha_1" || hash != "captcha_0" {
		t.Fatalf("field discovery wrong: field=%q hash=%q", field, hash)
	}
}

// TestResolveReference joins relative URLs against the page URL.
func TestResolveReference(t *testing.T) {
	base, _ := url.Parse("https://portal.example.com/graduate/signup")
	if got := resolveReference(base, "/captcha/img.png"); got != "https://portal.example.com/captcha/img.png" {
		t.Fatalf("got %q", got)
	}
	if got := resolveReference(base, "https://other.example.com/x.png"); got != "https://other.example.com/x.png" {
		t.Fatalf("got %q", got)
	}
	if got := resolveReference(nil, "/x.png"); got != "/x.png" {
		t.Fatalf("got %q", got)
	}
}

// TestDefaultFailureMarkersCoverCommonPhrasings guards the default marker list
// against regressions (the ospoly case said exactly "Invalid CAPTCHA").
func TestDefaultFailureMarkersCoverCommonPhrasings(t *testing.T) {
	if _, ok := containsFold(`<li>Invalid CAPTCHA</li>`, defaultFailureMarkers); !ok {
		t.Fatal("default markers must match 'Invalid CAPTCHA'")
	}
	for _, marker := range []string{"验证码错误", "Captcha is invalid", "incorrect captcha"} {
		if _, ok := containsFold("<p>"+marker+"</p>", defaultFailureMarkers); !ok {
			t.Fatalf("default markers must match %q", marker)
		}
	}
}

// TestTokenSolverValidation covers input validation without network.
func TestTokenSolverValidation(t *testing.T) {
	solver := NewTokenSolver("", "", nil)
	if _, err := solver.Solve(context.Background(), TokenRequest{Type: "turnstile", SiteKey: "k", PageURL: "https://x"}); err == nil {
		t.Fatal("expected missing-key error")
	}
	solver = NewTokenSolver("key", "", nil)
	if _, err := solver.Solve(context.Background(), TokenRequest{Type: "geetest", SiteKey: "k", PageURL: "https://x"}); err == nil || !strings.Contains(err.Error(), "unsupported captcha type") {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
	if _, err := solver.Solve(context.Background(), TokenRequest{Type: "turnstile"}); err == nil || !strings.Contains(err.Error(), "site_key and page_url are required") {
		t.Fatalf("expected missing sitekey error, got %v", err)
	}
}

// TestInjectJSEmbedsToken checks the injection script shape.
func TestInjectJSEmbedsToken(t *testing.T) {
	js := InjectJS("turnstile", "tok-123")
	if !strings.Contains(js, `"tok-123"`) {
		t.Fatalf("token not embedded: %s", js)
	}
	for _, field := range []string{"g-recaptcha-response", "cf-turnstile-response"} {
		if !strings.Contains(js, field) {
			t.Fatalf("field %s missing from inject js", field)
		}
	}
}
