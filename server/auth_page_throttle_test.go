package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/behemoth/agent"
)

func TestAuthPagePathClassification(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/login", true},
		{"GET", "/sign-up", true},
		{"POST", "/api/session", true},
		{"POST", "/account/password/reset", true},
		{"GET", "/auth/realms/acme/protocol/openid-connect/auth", true},
		{"GET", "/oauth2/authorize", true},
		{"GET", "/static/app.js", false},
		{"GET", "/auth/logo.png", false},
		{"GET", "/login/bundle.js?v=1", false},
		{"GET", "/api/v1/users", false},
		{"GET", "/", false},
		{"PUT", "/login", false},
		{"CONNECT", "", false},
	} {
		if got := authPagePath(tc.method, tc.path); got != tc.want {
			t.Errorf("authPagePath(%s %s)=%v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// fakeAuthGate returns a throttle with a controllable clock and wide burst cap.
func fakeAuthGate(t *testing.T) (*authPageThrottle, *time.Time) {
	t.Helper()
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	g := &authPageThrottle{
		hosts:         map[string]*authHostState{},
		now:           func() time.Time { return clock },
		perMinute:     3,
		perHour:       5,
		hostPerMinute: 1000,
		cooldown:      30 * time.Minute,
	}
	return g, &clock
}

func TestAuthPageThrottleBudgetWindows(t *testing.T) {
	g, clock := fakeAuthGate(t)
	for i := 0; i < 3; i++ {
		if code, _, _ := g.gate("GET", "shop.example.com", "/login"); code != 0 {
			t.Fatalf("attempt %d blocked: %d", i+1, code)
		}
	}
	code, retry, msg := g.gate("POST", "shop.example.com", "/login")
	if code != http.StatusTooManyRequests || retry <= 0 || !strings.Contains(msg, "in the last minute") {
		t.Fatalf("minute budget: code=%d retry=%d msg=%q", code, retry, msg)
	}
	// Non-auth paths are not subject to the auth budget.
	if code, _, _ := g.gate("GET", "shop.example.com", "/api/items"); code != 0 {
		t.Fatalf("api path blocked by auth budget: %d", code)
	}
	// A minute later the minute window frees up, but the shared hour budget still counts.
	*clock = clock.Add(61 * time.Second)
	for i := 0; i < 2; i++ {
		if code, _, _ := g.gate("GET", "shop.example.com", "/login"); code != 0 {
			t.Fatalf("post-minute attempt %d blocked: %d", i+1, code)
		}
	}
	code, retry, msg = g.gate("GET", "shop.example.com", "/login")
	if code != http.StatusTooManyRequests || retry < 3000 || !strings.Contains(msg, "last hour") {
		t.Fatalf("hour budget: code=%d retry=%d msg=%q", code, retry, msg)
	}
	// Other hosts keep their own budget.
	if code, _, _ := g.gate("GET", "other.example.com", "/login"); code != 0 {
		t.Fatalf("budget leaked across hosts: %d", code)
	}
}

func TestAuthPageThrottleCooldownOnProviderAuthRevoked(t *testing.T) {
	g, clock := fakeAuthGate(t)
	g.noteUpstream("shop.example.com", http.StatusProxyAuthRequired, "CONNECT", "")
	code, retry, msg := g.gate("GET", "shop.example.com", "/deep/link")
	if code != http.StatusTooManyRequests || retry <= 0 || !strings.Contains(msg, "cooldown") {
		t.Fatalf("cooldown not applied: code=%d retry=%d msg=%q", code, retry, msg)
	}
	*clock = clock.Add(31 * time.Minute)
	if code, _, _ := g.gate("GET", "shop.example.com", "/deep/link"); code != 0 {
		t.Fatalf("cooldown did not expire: %d", code)
	}
	// 403/429 only open a cooldown on auth pages.
	g.noteUpstream("api.example.com", http.StatusForbidden, "GET", "/api/v1/x")
	if code, _, _ := g.gate("GET", "api.example.com", "/api/v1/x"); code != 0 {
		t.Fatalf("non-auth 403 should not cool down: %d", code)
	}
	g.noteUpstream("api.example.com", http.StatusForbidden, "POST", "/login")
	if code, _, _ := g.gate("GET", "api.example.com", "/api/v1/x"); code == 0 {
		t.Fatal("auth 403 should cool down")
	}
}

func TestAuthPageThrottleBurstCapAndHostNormalization(t *testing.T) {
	g, _ := fakeAuthGate(t)
	g.hostPerMinute = 2
	if code, _, _ := g.gate("GET", "Example.com:8443", "/assets/a.css"); code != 0 {
		t.Fatalf("first request blocked: %d", code)
	}
	// Same host, different spelling: the burst cap must be shared.
	if code, _, _ := g.gate("GET", "www.Example.com:8443", "/assets/b.css"); code != 0 {
		t.Fatalf("second request blocked: %d", code)
	}
	code, retry, msg := g.gate("GET", "example.com", "/assets/c.css")
	if code != http.StatusTooManyRequests || retry <= 0 || !strings.Contains(msg, "burst cap") {
		t.Fatalf("burst cap: code=%d retry=%d msg=%q", code, retry, msg)
	}
}

func TestAuthPageThrottleDisabled(t *testing.T) {
	t.Setenv("BEHEMOTH_AUTH_THROTTLE", "0")
	g := newAuthPageThrottle()
	g.hostPerMinute, g.perMinute, g.perHour = 1, 1, 1
	for i := 0; i < 5; i++ {
		if code, _, _ := g.gate("GET", "example.com", "/login"); code != 0 {
			t.Fatalf("disabled throttle blocked request %d", i)
		}
	}
}

// Forward proxy end-to-end: a blocked auth page must come back as 429 with a
// Retry-After header instead of reaching the upstream.
func TestForwardProxyAuthGate(t *testing.T) {
	var hits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	pu, _ := url.Parse(upstream.URL)

	g := newAuthPageThrottle()
	g.perMinute, g.perHour, g.hostPerMinute = 1, 5, 1000

	fp, err := newDynamicForwardProxy(func() string { return pu.String() })
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	fp.guardRequest = func(_ context.Context, method, host, path string) (int, int, string) {
		return g.gate(method, host, path)
	}

	proxyURL, err := url.Parse(fp.Addr())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://login.example.test/login")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first login request: %d", resp.StatusCode)
	}
	resp, err = client.Get("http://login.example.test/login?next=/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second login request: %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
	if hits != 1 {
		t.Fatalf("upstream hits=%d, want 1", hits)
	}
}

func TestAuthPageThrottlePortsAndScrapedExemptionAndRevokedQuarantine(t *testing.T) {
	g, _ := fakeAuthGate(t)
	g.perMinute = 2

	// 1. Outbound SMTP mail-relay port 25/587 blocked with 403
	if code, _, _ := g.gate("CONNECT", "mail.target.test:25", ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 on port 25, got %d", code)
	}
	// 2. Non-HTTP credential port 21 (FTP) counted against authSent budget
	if code, _, _ := g.gate("CONNECT", "ftp.target.test:21", ""); code != 0 {
		t.Fatalf("first FTP connect blocked: %d", code)
	}
	if code, _, _ := g.gate("CONNECT", "ftp.target.test:21", ""); code != 0 {
		t.Fatalf("second FTP connect blocked: %d", code)
	}
	if code, _, _ := g.gate("CONNECT", "ftp.target.test:21", ""); code != http.StatusTooManyRequests {
		t.Fatalf("third FTP connect should hit auth minute budget, got %d", code)
	}

	// 3. Scraped unauthenticated proxies and Tor are exempt; Webshare/commercial proxies are metered
	m := &Manager{
		proxyPool: &proxyPoolState{
			active: "scraped-http-1-2-3-4-8080",
			entries: []proxyPoolEntry{
				{
					ProxyPoolEntry: ProxyPoolEntry{ID: "scraped-http-1-2-3-4-8080", Enabled: true, Health: "healthy"},
					RawURL:         "http://1.2.3.4:8080",
				},
				{
					ProxyPoolEntry: ProxyPoolEntry{ID: "ws-1", Name: "Webshare US", Enabled: true, Health: "healthy"},
					RawURL:         "http://wsuser:wspass@198.51.100.10:80",
				},
				{
					ProxyPoolEntry: ProxyPoolEntry{ID: "ws-2", Name: "Webshare Backup", Enabled: true, Health: "healthy"},
					RawURL:         "http://wsuser:wspass@198.51.100.11:80",
				},
			},
		},
	}
	if m.IsMeteredCommercialProxyActive() {
		t.Fatal("unauthenticated scraped-* proxy must be exempt from commercial provider meter")
	}
	m.proxyPool.active = "ws-1"
	if !m.IsMeteredCommercialProxyActive() {
		t.Fatal("authenticated Webshare proxy must be treated as metered commercial proxy")
	}

	// 4. HTTP 407 auth-revoked quarantines ws-1 and rotates to ws-2 immediately
	m.quarantineUpstreamProxy("http://wsuser:wspass@198.51.100.10:80", "HTTP 407 revoked")
	if m.proxyPool.entries[1].Health != "unhealthy-cooling" {
		t.Fatalf("expected ws-1 unhealthy-cooling after 407, got %s", m.proxyPool.entries[1].Health)
	}
	if m.proxyPool.active != "ws-2" {
		t.Fatalf("expected automatic failover from ws-1 to ws-2, got active=%s", m.proxyPool.active)
	}
}

func TestCooldownResumeScheduleAndCancelTools(t *testing.T) {
	m := proxyTestManager(t)
	s := &Server{m: m, chatBusy: map[string]bool{}}

	conv, err := m.pg.CreateConversation("auto", "portal.example.com", nil)
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{SessionID: s.convBusyKey(conv.ID)})

	in, _ := json.Marshal(map[string]any{
		"cooldown_minutes":        35,
		"repeat_interval_minutes": 45,
		"max_runs":                3,
		"domain":                  "portal.example.com",
		"reason":                  "5/hour Webshare auth batch reached",
		"resume_prompt":           "Continue credential batch #2 (users 6-10) spaced 12s apart.",
	})
	res, err := s.toolScheduleCooldownResume().Call(ctx, in, nil)
	if err != nil || res.IsError {
		t.Fatalf("schedule_cooldown_resume failed: err=%v res=%s", err, res.Flatten())
	}
	var out struct {
		OK  bool              `json:"ok"`
		Job CooldownResumeJob `json:"job"`
	}
	if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil || !out.OK || out.Job.ConversationID != conv.ID {
		t.Fatalf("unexpected schedule output: %s (err=%v)", res.Content[0].Text, err)
	}

	listRes, err := s.toolListCooldownSchedules().Call(ctx, json.RawMessage(`{}`), nil)
	if err != nil || !strings.Contains(listRes.Flatten(), out.Job.ID) {
		t.Fatalf("expected job in list_cooldown_schedules, got %s", listRes.Flatten())
	}

	cancelIn, _ := json.Marshal(map[string]any{"job_id": out.Job.ID})
	cancelRes, err := s.toolCancelCooldownSchedule().Call(ctx, cancelIn, nil)
	if err != nil || !strings.Contains(cancelRes.Flatten(), `"ok":true`) {
		t.Fatalf("cancel_cooldown_schedule failed: err=%v res=%s", err, cancelRes.Flatten())
	}
}
