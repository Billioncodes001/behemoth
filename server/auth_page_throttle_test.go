package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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
