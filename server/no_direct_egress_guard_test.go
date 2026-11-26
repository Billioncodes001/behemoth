package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	proxyv2 "github.com/Autumn-27/behemoth/server/proxy/v2"
)

// connectViaProxy issues a raw HTTP CONNECT through the local forwarder and
// returns the upstream connection (or the proxy's error response).
func connectViaProxy(t *testing.T, proxyAddr, target string) (net.Conn, *http.Response, error) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxyAddr, "http://"))
	if err != nil {
		return nil, nil, err
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, resp, nil
}

// TestNoDirectEgressGuardBlocksDirectWhenNoProxy verifies the HARD no-direct
// rule: with no outbound proxy available (Pool/Tor/Global all off) and
// BEHEMOTH_ALLOW_DIRECT_EGRESS unset, the local forwarder must answer 503 for
// every non-loopback external request (plain HTTP and CONNECT) instead of
// dialing direct, while loopback targets (local PoC servers) still pass.
func TestNoDirectEgressGuardBlocksDirectWhenNoProxy(t *testing.T) {
	t.Setenv("BEHEMOTH_ALLOW_DIRECT_EGRESS", "")
	if directEgressAllowed() {
		t.Fatal("direct egress must be blocked by default")
	}

	var directHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits++
		_, _ = io.WriteString(w, "direct-hit")
	}))
	defer target.Close()

	fp, err := newDynamicForwardProxy(func() string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	fp.direct = directEgressAllowed // mirror the Manager wiring

	pu, _ := url.Parse(fp.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}

	// Non-loopback external target: must be blocked with 503 before any dial.
	resp, err := client.Get("http://example.test/check")
	if err != nil {
		t.Fatalf("request via forwarder failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 no-direct guard, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Fail-Closed Proxy Guard") || !strings.Contains(string(body), "no usable outbound proxy") {
		t.Fatalf("unexpected guard message: %q", string(body))
	}
	if directHits != 0 {
		t.Fatalf("expected 0 direct target hits while blocked, got %d", directHits)
	}

	// CONNECT tunnel to an external host must be blocked the same way.
	conn, cresp, err := connectViaProxy(t, fp.Addr(), "example.test:443")
	if err == nil && cresp != nil && cresp.StatusCode == http.StatusOK {
		_ = conn.Close()
		t.Fatal("expected CONNECT to be blocked by the no-direct guard")
	}
	if err == nil && cresp != nil {
		_ = conn.Close()
		if cresp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(readBody(cresp), "Fail-Closed Proxy Guard") {
			t.Fatalf("unexpected CONNECT guard response: %d %q", cresp.StatusCode, readBody(cresp))
		}
	}

	// Loopback targets (local PoC servers) must never be routed upstream/blocked.
	lbURL, _ := url.Parse(target.URL)
	lbResp, err := client.Get("http://" + lbURL.Host + "/poc")
	if err != nil {
		t.Fatalf("loopback request via forwarder failed: %v", err)
	}
	lbBody, _ := io.ReadAll(lbResp.Body)
	_ = lbResp.Body.Close()
	if lbResp.StatusCode != http.StatusOK || string(lbBody) != "direct-hit" {
		t.Fatalf("expected loopback passthrough, got %d %q", lbResp.StatusCode, string(lbBody))
	}
	if directHits != 1 {
		t.Fatalf("expected exactly 1 direct loopback hit, got %d", directHits)
	}
}

func readBody(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return string(b)
}

// TestNoDirectEgressGuardEnvOverride verifies BEHEMOTH_ALLOW_DIRECT_EGRESS=1
// restores legacy direct egress through the forwarder.
func TestNoDirectEgressGuardEnvOverride(t *testing.T) {
	t.Setenv("BEHEMOTH_ALLOW_DIRECT_EGRESS", "1")
	if !directEgressAllowed() {
		t.Fatal("expected direct egress allowed with env override")
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct-ok")
	}))
	defer target.Close()

	fp, err := newDynamicForwardProxy(func() string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	fp.direct = directEgressAllowed

	pu, _ := url.Parse(fp.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	tu, _ := url.Parse(target.URL)
	resp, err := client.Get("http://" + tu.Host + "/x")
	if err != nil {
		t.Fatalf("direct request via forwarder failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "direct-ok" {
		t.Fatalf("expected direct passthrough with env override, got %d %q", resp.StatusCode, string(body))
	}
}

// TestNoOutboundDirectBlockedRoutingModeAndScrapedVisibility verifies the
// check_proxy_status/get_proxy_pool_status payload: the new blocked routing
// mode, the STOP instruction, and scraped-proxy auto-detection surfacing.
func TestNoOutboundDirectBlockedRoutingModeAndScrapedVisibility(t *testing.T) {
	t.Setenv("BEHEMOTH_ALLOW_DIRECT_EGRESS", "")

	m := proxyTestManager(t)
	// Hermetic: earlier tests in the shared test DB may have persisted a static
	// Global Proxy — wipe it so this manager really has zero outbound egress.
	_ = m.pg.SetSetting(settingStaticGlobalProxy, "")
	_ = m.pg.SetSetting(settingGlobalProxy, "")
	_ = m.pg.SetSetting(settingProxyPool, "")
	_ = m.pg.SetSetting(settingProxyPoolActive, "")
	m.mu.Lock()
	m.userStaticGlobal, m.globalProxy = "", ""
	m.mu.Unlock()

	s := &Server{m: m}
	pool := proxyv2.NewPool(nil)
	ppV2 = &proxyPoolV2{Pool: pool, Handler: proxyv2.NewHandler(pool)}
	defer func() { ppV2 = nil }()
	pool.SetSyncHook(func(proxies []proxyv2.ProxyInfo, activeID string, cfg *proxyv2.ProxyPoolConfig) {
		s.syncProxyPoolV2ToV1(proxies, activeID, cfg)
	})

	// Stage a verified scraped proxy while the pool stays disabled.
	if err := pool.ReplaceManagedPrefixProxies("scraped-", []proxyv2.ProxyInfo{{
		ID: "scraped-http-1-2-3-4-1080", Type: proxyv2.ProxyTypeHTTP,
		Host: "1.2.3.4", Port: 1080, Status: proxyv2.StatusHealthy, Active: true,
		Country: "US", LatencyMS: 250,
	}}, false); err != nil {
		t.Fatalf("stage scraped proxy: %v", err)
	}
	cfg := pool.GetConfig()
	cfg.Enabled = false
	_ = pool.UpdateConfig(cfg)

	payload, err := s.buildProxyStatusPayload()
	if err != nil {
		t.Fatalf("buildProxyStatusPayload: %v", err)
	}
	if payload["effective_routing_mode"] != "no_outbound_direct_blocked" {
		t.Fatalf("expected no_outbound_direct_blocked, got %v", payload["effective_routing_mode"])
	}
	if payload["proxy_enabled"] != false || payload["direct_egress_blocked"] != true || payload["direct_egress_allowed"] != false {
		t.Fatalf("expected proxy_enabled=false with direct egress blocked, got %+v", payload)
	}
	instr, _ := payload["instruction"].(string)
	if !strings.Contains(instr, "STOP WORK IMMEDIATELY") || !strings.Contains(instr, "NEVER connect directly") {
		t.Fatalf("expected STOP instruction in blocked mode, got %q", instr)
	}
	scraped, _ := payload["scraped_proxies"].(map[string]any)
	if scraped == nil {
		t.Fatalf("expected scraped_proxies in payload, got %+v", payload)
	}
	if scraped["total"] != 1 || scraped["active_verified"] != 1 {
		t.Fatalf("expected 1 active scraped proxy surfaced, got %+v", scraped)
	}
	if !strings.Contains(instr, "SCRAPED PROXIES AVAILABLE") {
		t.Fatalf("expected scraped-proxy activation hint, got %q", instr)
	}

	// With the env override, the same state must report plain direct mode.
	t.Setenv("BEHEMOTH_ALLOW_DIRECT_EGRESS", "1")
	payload, err = s.buildProxyStatusPayload()
	if err != nil {
		t.Fatalf("buildProxyStatusPayload(override): %v", err)
	}
	if payload["effective_routing_mode"] != "direct" || payload["direct_egress_allowed"] != true {
		t.Fatalf("expected direct mode with env override, got %+v", payload)
	}
}
