package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoopholeSolveCaptchaHonorsOutboundProxyAndFailClosed(t *testing.T) {
	var directHits atomic.Int32
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	m := &Manager{}
	m.SetProxyPoolFailClosed(true)
	s := &Server{m: m}
	runCaptcha := solveCaptchaRun(s)

	for _, mode := range []string{"form", "ocr"} {
		payload, _ := json.Marshal(map[string]any{
			"mode":      mode,
			"page_url":  targetSrv.URL,
			"image_url": targetSrv.URL + "/captcha.png",
		})
		res, err := runCaptcha(context.Background(), payload)
		if err != nil {
			t.Fatalf("mode=%s unexpected error: %v", mode, err)
		}
		if !strings.Contains(res.Flatten(), "Fail-Closed Proxy Guard") {
			t.Fatalf("mode=%s expected Fail-Closed Proxy Guard, got: %s", mode, res.Flatten())
		}
	}
	if directHits.Load() != 0 {
		t.Fatalf("expected 0 direct target hits during Fail-Closed, got %d", directHits.Load())
	}

	// Verify automatic OutboundProxy / GlobalProxy fallback when `proxy` param is omitted.
	var proxyHits atomic.Int32
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxySrv.Close()

	m.SetProxyPoolFailClosed(false)
	m.globalProxy = proxySrv.URL
	ocrPayload, _ := json.Marshal(map[string]any{
		"mode":      "ocr",
		"image_url": "http://captcha-target.example/challenge.png",
	})
	_, _ = runCaptcha(context.Background(), ocrPayload)
	if proxyHits.Load() == 0 {
		t.Fatal("expected solve_captcha (without explicit proxy arg) to route through configured outbound proxy")
	}
}

func TestLoopholeRepeaterAndCustomHTTPFailClosedGuard(t *testing.T) {
	t.Setenv(repeaterAllowLocalEnv, "1")
	var directHits atomic.Int32
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("leaked"))
	}))
	defer targetSrv.Close()

	m := &Manager{}
	m.SetProxyPoolFailClosed(true)
	s := &Server{m: m}

	for _, useRecording := range []bool{true, false} {
		code, out, raw := repeaterTestSend(t, s, map[string]any{
			"url":                 targetSrv.URL,
			"use_recording_proxy": useRecording,
		})
		if code != http.StatusOK || out.Status != 0 || !strings.Contains(out.Error, "Fail-Closed Proxy Guard") {
			t.Fatalf("use_recording_proxy=%v expected Fail-Closed error, got code=%d out=%+v raw=%s", useRecording, code, out, raw)
		}
	}

	// Also verify httpProxyTransport directly for custom HTTP tools with UseRecordingProxy=false.
	tr := s.httpProxyTransport(httpExec{UseRecordingProxy: false})
	if tr == nil {
		t.Fatal("expected non-nil fail-closed transport when IsProxyPoolFailClosed is true")
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	if resp, err := client.Get(targetSrv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected custom HTTP client to fail closed")
	} else if !strings.Contains(err.Error(), "Fail-Closed Proxy Guard") {
		t.Fatalf("expected Fail-Closed Proxy Guard error, got %v", err)
	}

	if directHits.Load() != 0 {
		t.Fatalf("expected 0 direct hits while Fail-Closed is active, got %d", directHits.Load())
	}
}

func TestLoopholeWorkspaceSymlinkContainment(t *testing.T) {
	workDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideSecret := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideSecret, []byte("TOP-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: &Manager{dir: workDir}}

	// 1. Legitimate internal symlink (sessions/conv-9/app.example.com -> domains/app.example.com) MUST work!
	s.ensureDomainWorkspaceStructure("app.example.com", "conv-9")
	if abs, ok := s.wsResolve("sessions/conv-9/app.example.com/CREDENTIALS.md"); !ok || abs == "" {
		t.Fatal("expected internal domain workspace symlink to remain allowed")
	}

	// 2. External file & directory symlinks inside sessions/conv-9 MUST be blocked!
	sessDir := filepath.Join(workDir, "sessions", "conv-9")
	_ = os.Symlink(outsideSecret, filepath.Join(sessDir, "leak.txt"))
	_ = os.Symlink(outsideDir, filepath.Join(sessDir, "escape_dir"))

	for _, badRel := range []string{
		"sessions/conv-9/leak.txt",
		"sessions/conv-9/escape_dir",
		"sessions/conv-9/escape_dir/secret.txt",
		"sessions/conv-9/escape_dir/new_pwn.txt",
	} {
		if abs, ok := s.wsResolve(badRel); ok {
			t.Fatalf("wsResolve(%q) unexpectedly allowed external symlink escape -> %s", badRel, abs)
		}
	}

	// Verify HTTP handlers reject external symlink read/download/write and wsList omits them.
	rRead := httptest.NewRequest(http.MethodGet, "/api/workspace/read?path=sessions/conv-9/leak.txt", nil)
	wRead := httptest.NewRecorder()
	s.wsRead(wRead, rRead)
	if wRead.Code != http.StatusBadRequest {
		t.Fatalf("wsRead external symlink code=%d body=%s", wRead.Code, wRead.Body.String())
	}

	rDl := httptest.NewRequest(http.MethodGet, "/api/workspace/download?path=sessions/conv-9/leak.txt", nil)
	wDl := httptest.NewRecorder()
	s.wsDownload(wDl, rDl)
	if wDl.Code != http.StatusBadRequest || strings.Contains(wDl.Body.String(), "TOP-SECRET") {
		t.Fatalf("wsDownload external symlink code=%d body=%s", wDl.Code, wDl.Body.String())
	}

	rWrite := httptest.NewRequest(http.MethodPost, "/api/workspace/write", strings.NewReader(`{"path":"sessions/conv-9/escape_dir/pwn.txt","content":"x"}`))
	wWrite := httptest.NewRecorder()
	s.wsWrite(wWrite, rWrite)
	if wWrite.Code != http.StatusBadRequest {
		t.Fatalf("wsWrite external symlink code=%d body=%s", wWrite.Code, wWrite.Body.String())
	}

	rList := httptest.NewRequest(http.MethodGet, "/api/workspace/list?path=sessions/conv-9", nil)
	wList := httptest.NewRecorder()
	s.wsList(wList, rList)
	if strings.Contains(wList.Body.String(), "leak.txt") || strings.Contains(wList.Body.String(), "escape_dir") {
		t.Fatalf("wsList exposed external symlinks: %s", wList.Body.String())
	}
	if !strings.Contains(wList.Body.String(), "app.example.com") {
		t.Fatalf("wsList hid legitimate internal domain symlink: %s", wList.Body.String())
	}
}

func TestLoopholeGitWebhookAuthAndCooldown(t *testing.T) {
	maintState.mu.Lock()
	maintState.LastWebhookCall = time.Time{}
	maintState.mu.Unlock()
	t.Cleanup(func() {
		maintState.mu.Lock()
		maintState.LastWebhookCall = time.Time{}
		maintState.mu.Unlock()
	})

	s := &Server{} // s.ctx is nil so background git fetch is safely skipped in unit test
	t.Setenv("BEHEMOTH_WEBHOOK_SECRET", "super-secret-key")

	// 1. Missing token/signature -> 401
	w1 := httptest.NewRecorder()
	s.handleTriggerGitSync(w1, httptest.NewRequest(http.MethodPost, "/api/update/webhook", strings.NewReader(`{}`)))
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without secret, got %d", w1.Code)
	}

	// 2. Valid GitHub X-Hub-Signature-256 -> 202 Accepted
	payload := []byte(`{"ref":"refs/heads/main"}`)
	mac := hmac.New(sha256.New, []byte("super-secret-key"))
	_, _ = mac.Write(payload)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req2 := httptest.NewRequest(http.MethodPost, "/api/update/webhook", bytes.NewReader(payload))
	req2.Header.Set("X-Hub-Signature-256", sig)
	w2 := httptest.NewRecorder()
	s.handleTriggerGitSync(w2, req2)
	if w2.Code != http.StatusAccepted {
		t.Fatalf("expected 202 with valid HMAC signature, got %d: %s", w2.Code, w2.Body.String())
	}

	// 3. Immediate second public webhook call within cooldown -> 429 Too Many Requests
	req3 := httptest.NewRequest(http.MethodPost, "/api/update/webhook", bytes.NewReader(payload))
	req3.Header.Set("X-Behemoth-Webhook-Token", "super-secret-key")
	w3 := httptest.NewRecorder()
	s.handleTriggerGitSync(w3, req3)
	if w3.Code != http.StatusTooManyRequests || w3.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 rate limit during cooldown, got %d", w3.Code)
	}

	// 4. Authenticated admin endpoint (/api/update/git-sync) is NOT blocked by public webhook cooldown
	w4 := httptest.NewRecorder()
	s.handleTriggerGitSync(w4, httptest.NewRequest(http.MethodPost, "/api/update/git-sync", nil))
	if w4.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for authenticated git-sync, got %d", w4.Code)
	}
}

func TestLoopholeScraperPublicFeedSSRFGuard(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1:8787/api/settings",
		"http://localhost/proxies.txt",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/proxies.txt",
		"http://172.16.4.2/proxies.txt",
		"http://192.168.1.1/proxies.txt",
		"http://100.64.0.10/proxies.txt",
		"http://[::1]:8080/proxies.txt",
		"http://0x7f000001/proxies.txt",
		"http://2130706433/proxies.txt",
		"http://metadata.internal/proxies.txt",
		"file:///etc/passwd",
	}
	for _, raw := range blocked {
		if _, err := validatePublicScrapeFeedURL(raw); err == nil {
			t.Errorf("validatePublicScrapeFeedURL(%q) unexpectedly allowed non-public SSRF target", raw)
		}
	}
	if _, err := validatePublicScrapeFeedURL("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt"); err != nil {
		t.Fatalf("expected public GitHub feed URL to pass validation, got %v", err)
	}
	if err := scraperBlockNonPublicDial("tcp", "169.254.169.254:80", nil); err == nil {
		t.Fatal("expected scraperBlockNonPublicDial to reject cloud metadata IP")
	}
	if err := scraperBlockNonPublicDial("tcp", "10.1.2.3:443", nil); err == nil {
		t.Fatal("expected scraperBlockNonPublicDial to reject RFC1918 private IP")
	}
	if err := scraperBlockNonPublicDial("tcp", "185.199.108.133:443", nil); err != nil {
		t.Fatalf("expected public IP dial to pass, got %v", err)
	}
}
