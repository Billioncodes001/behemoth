package traffic

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateProxyURL(t *testing.T) {
	ok := []string{
		"http://127.0.0.1:8080",
		"https://proxy.example.com:3128",
		"socks5://10.0.0.1:1080",
		"socks5://user:pass@10.0.0.1:1080",
	}
	for _, raw := range ok {
		if _, err := ValidateProxyURL(raw); err != nil {
			t.Errorf("ValidateProxyURL(%q) unexpected error: %v", raw, err)
		}
	}
	bad := []string{
		"127.0.0.1:8080",         // no scheme
		"ftp://host:21",          // unsupported scheme
		"http://",                // no host
		"socks4://10.0.0.1:1080", // unsupported scheme
	}
	for _, raw := range bad {
		if _, err := ValidateProxyURL(raw); err == nil {
			t.Errorf("ValidateProxyURL(%q) expected error, got nil", raw)
		}
	}
}

func TestSetUpstreamProxyStoreClear(t *testing.T) {
	tr := &Traffic{}
	if got := tr.upstream.Load(); got != nil {
		t.Fatalf("initial upstream = %v, want nil", got)
	}
	if err := tr.SetUpstreamProxy("socks5://user:pass@10.0.0.1:1080"); err != nil {
		t.Fatalf("SetUpstreamProxy: %v", err)
	}
	u := tr.upstream.Load()
	if u == nil || u.Scheme != "socks5" || u.Host != "10.0.0.1:1080" {
		t.Fatalf("stored upstream = %v, want socks5://10.0.0.1:1080", u)
	}
	if pw, _ := u.User.Password(); u.User.Username() != "user" || pw != "pass" {
		t.Fatalf("stored upstream lost credentials: %v", u)
	}
	// Empty clears back to direct.
	if err := tr.SetUpstreamProxy("  "); err != nil {
		t.Fatalf("SetUpstreamProxy(clear): %v", err)
	}
	if got := tr.upstream.Load(); got != nil {
		t.Fatalf("after clear upstream = %v, want nil", got)
	}
	// Invalid value is rejected and does not mutate current state.
	if err := tr.SetUpstreamProxy("nope://x"); err == nil {
		t.Fatal("SetUpstreamProxy(invalid) expected error")
	}
	if got := tr.upstream.Load(); got != nil {
		t.Fatalf("invalid set mutated upstream to %v, want nil", got)
	}
}

func TestProxyAddr(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		// Bare :port means "bind all interfaces" — the legacy default. The URL
		// agents consume must still point at loopback so they reach the local proxy.
		{":8788", "http://127.0.0.1:8788"},
		// Explicit loopback — the current default since #129 (open proxy exposure).
		{"127.0.0.1:8788", "http://127.0.0.1:8788"},
		// Explicit all-interface bind is still supported (remote capture via SSH).
		{"0.0.0.0:8788", "http://0.0.0.0:8788"},
	}
	for _, c := range cases {
		got := (&Traffic{addr: c.addr}).ProxyAddr()
		if got != c.want {
			t.Errorf("ProxyAddr(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}
func TestResolveUpstreamPrefersLiveProvider(t *testing.T) {
	tr := &Traffic{}
	if err := tr.SetUpstreamProxy("http://static.example:8080"); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	tr.SetUpstreamProvider(func() string {
		n := calls.Add(1)
		if n%2 == 0 {
			return "socks5://circuit-b:19051"
		}
		return "socks5://circuit-a:19050"
	})
	req := &http.Request{Host: "target.example", URL: &url.URL{Host: "target.example"}}

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		u, err := tr.resolveUpstream(req)
		if err != nil {
			t.Fatalf("resolveUpstream: %v", err)
		}
		if u == nil || strings.Contains(u.Host, "static") {
			t.Fatalf("provider did not win over static upstream: %v", u)
		}
		seen[u.Host] = true
	}
	if !seen["circuit-a:19050"] || !seen["circuit-b:19051"] {
		t.Fatalf("expected rotation across both provider values, saw %v", seen)
	}
}

func TestResolveUpstreamFallsBackToStaticThenFailClosed(t *testing.T) {
	tr := &Traffic{}
	tr.SetUpstreamProvider(func() string { return "  " })
	if err := tr.SetUpstreamProxy("http://static.example:8080"); err != nil {
		t.Fatal(err)
	}
	req := &http.Request{Host: "target.example", URL: &url.URL{Host: "target.example"}}
	u, err := tr.resolveUpstream(req)
	if err != nil || u == nil || u.Host != "static.example:8080" {
		t.Fatalf("blank provider must fall back to the static upstream, got u=%v err=%v", u, err)
	}

	// No provider, no static upstream and fail-closed: direct dials must be blocked.
	if err := tr.SetUpstreamProxy(""); err != nil {
		t.Fatal(err)
	}
	tr.SetUpstreamProvider(nil)
	tr.SetFailClosed(true)
	if u, err := tr.resolveUpstream(req); err == nil || u != nil {
		t.Fatalf("expected fail-closed error, got u=%v err=%v", u, err)
	}

	// A live provider re-opens egress even while fail-closed is latched.
	tr.SetUpstreamProvider(func() string { return "socks5://127.0.0.1:19050" })
	if u, err := tr.resolveUpstream(req); err != nil || u == nil || u.Host != "127.0.0.1:19050" {
		t.Fatalf("provider must satisfy the fail-closed guard, got u=%v err=%v", u, err)
	}
}

func TestResolveUpstreamLoopbackBypassesEverything(t *testing.T) {
	tr := &Traffic{}
	tr.SetFailClosed(true)
	tr.SetUpstreamProvider(func() string { return "socks5://127.0.0.1:19050" })
	for _, host := range []string{"127.0.0.1:8899", "localhost:3000", "[::1]:80"} {
		req := &http.Request{Host: host, URL: &url.URL{Host: host}}
		if u, err := tr.resolveUpstream(req); err != nil || u != nil {
			t.Fatalf("loopback %s must dial direct, got u=%v err=%v", host, u, err)
		}
	}
}
