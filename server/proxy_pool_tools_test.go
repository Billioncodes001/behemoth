package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/agent"
	proxyv2 "github.com/Autumn-27/artex/server/proxy/v2"
)

func TestAgentImportAndTestProxiesToolAndMidSessionRouting(t *testing.T) {
	// Spin up a local HTTP proxy + target server to verify real end-to-end routing.
	var proxyHits atomic.Int64
	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "routed-via-agent-proxy")
	}))
	defer upstreamProxy.Close()

	pu, _ := url.Parse(upstreamProxy.URL)
	host, portStr, _ := net.SplitHostPort(pu.Host)

	m := proxyTestManager(t)
	s := &Server{m: m}

	pool := proxyv2.NewPool(nil)
	ppV2 = &proxyPoolV2{
		Pool:    pool,
		Handler: proxyv2.NewHandler(pool),
	}
	pool.SetSyncHook(func(proxies []proxyv2.ProxyInfo, activeID string, cfg *proxyv2.ProxyPoolConfig) {
		s.syncProxyPoolV2ToV1(proxies, activeID, cfg)
	})

	// Before any proxy is enabled (Proxy Pool OFF, Global Proxy empty, Traffic Capture OFF):
	// SessionProxyAddr MUST be empty ("") and check_proxy_status MUST report proxy_enabled=false!
	if got := s.m.SessionProxyAddr(); got != "" {
		t.Fatalf("expected empty SessionProxyAddr when all proxies are disabled, got %q", got)
	}
	chkRes, err := s.toolCheckProxyStatus().Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil || chkRes.IsError {
		t.Fatalf("check_proxy_status failed: err=%v res=%+v", err, chkRes)
	}
	var chkPayload map[string]any
	if err := json.Unmarshal([]byte(chkRes.Content[0].Text), &chkPayload); err != nil {
		t.Fatalf("invalid check_proxy_status JSON: %v", err)
	}
	if chkPayload["proxy_enabled"] != false || chkPayload["effective_routing_mode"] != "direct" {
		t.Fatalf("expected proxy_enabled=false & direct before import, got %+v", chkPayload)
	}

	// Write a Webshare-format file in a temp workspace and call import_and_test_proxies
	tmpFile := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(tmpFile, []byte(host+":"+portStr+":demoUser:demoPass\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	inJSON, _ := json.Marshal(map[string]any{
		"file_path": tmpFile,
		"auto_test": false, // skip public internet ipify check in offline unit test
	})
	res, err := s.toolImportAndTestProxies().Call(context.Background(), inJSON, nil)
	if err != nil || res.IsError {
		t.Fatalf("import_and_test_proxies failed: err=%v res=%+v", err, res)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].Text), &payload); err != nil {
		t.Fatalf("invalid tool JSON: %v", err)
	}
	if int(payload["imported"].(float64)) != 1 || payload["pool_enabled"] != true {
		t.Fatalf("unexpected import payload: %+v", payload)
	}

	// Now that Proxy Pool is enabled, SessionProxyAddr immediately resolves to the local forwarder!
	sessionProxy := s.m.SessionProxyAddr()
	if !strings.HasPrefix(sessionProxy, "http://127.0.0.1:") {
		t.Fatalf("expected active local session forwarder after enabling pool, got %q", sessionProxy)
	}

	// Verify subsequent HTTP traffic using the pre-existing sessionProxy routes through the newly imported proxy!
	spURL, _ := url.Parse(sessionProxy)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(spURL)}}
	resp, err := client.Get("http://example.test/check")
	if err != nil {
		t.Fatalf("request through sessionProxy failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "routed-via-agent-proxy" || proxyHits.Load() == 0 {
		t.Fatalf("expected request routed through imported proxy, got body=%q hits=%d", string(body), proxyHits.Load())
	}

	// Verify disabling Proxy Pool switches to direct without clobbering proxy health,
	// and re-enabling + configuring restores pool routing immediately.
	disRes, err := s.toolManageProxyPool().Call(context.Background(), json.RawMessage(`{"action":"disable"}`), nil)
	if err != nil || disRes.IsError {
		t.Fatalf("manage_proxy_pool disable failed: err=%v res=%+v", err, disRes)
	}
	stRes, _ := s.toolGetProxyPoolStatus().Call(context.Background(), json.RawMessage(`{}`), nil)
	if !strings.Contains(stRes.Content[0].Text, `"effective_routing_mode":"direct"`) {
		t.Fatalf("expected direct routing when pool disabled, got %s", stRes.Content[0].Text)
	}

	enRes, err := s.toolManageProxyPool().Call(context.Background(), json.RawMessage(`{"action":"enable","rotation_strategy":"least_used","session_sticky":false,"rotation_interval_seconds":15}`), nil)
	if err != nil || enRes.IsError {
		t.Fatalf("manage_proxy_pool enable/configure failed: err=%v res=%+v", err, enRes)
	}
	stRes2, _ := s.toolGetProxyPoolStatus().Call(context.Background(), json.RawMessage(`{}`), nil)
	if !strings.Contains(stRes2.Content[0].Text, `"effective_routing_mode":"proxy_pool"`) {
		t.Fatalf("expected proxy_pool routing restored after re-enable, got %s", stRes2.Content[0].Text)
	}
}

func TestProxyPoolFailClosedBlocksDirectAndAbortsChatsWhenAllUnhealthy(t *testing.T) {
	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ip":"203.0.113.42"}`)
	}))
	pu, _ := url.Parse(upstreamProxy.URL)
	host, portStr, _ := net.SplitHostPort(pu.Host)

	m := proxyTestManager(t)
	chatCtx, chatCancel := context.WithCancelCause(context.Background())
	defer chatCancel(nil)
	s := &Server{
		m:          m,
		chatBusy:   map[string]bool{"conv-99": true},
		chatCancel: map[string]context.CancelCauseFunc{"conv-99": chatCancel},
	}

	pool := proxyv2.NewPool(nil)
	ppV2 = &proxyPoolV2{
		Pool:    pool,
		Handler: proxyv2.NewHandler(pool),
	}
	pool.SetSyncHook(func(proxies []proxyv2.ProxyInfo, activeID string, cfg *proxyv2.ProxyPoolConfig) {
		s.syncProxyPoolV2ToV1(proxies, activeID, cfg)
	})

	if _, err := pool.ImportProxies(host+":"+portStr, proxyv2.ProxyTypeHTTP); err != nil {
		t.Fatal(err)
	}
	pxList := pool.GetProxies()
	if err := pool.ActivateProxy(pxList[0].ID); err != nil {
		t.Fatal(err)
	}
	s.syncProxyPoolNow()

	// Kill the upstream proxy so all proxies in the enabled pool become unhealthy/stale.
	upstreamProxy.Close()

	// Agent quarantines the failing proxy via manage_proxy_pool(action="disable_proxy").
	// Pool MUST remain enabled (fail-closed) rather than auto-disabling and falling back to direct!
	quarRes, err := s.toolManageProxyPool().Call(context.Background(), json.RawMessage(`{"action":"disable_proxy","proxy_id":"`+pxList[0].ID+`"}`), nil)
	if err != nil || quarRes.IsError {
		t.Fatalf("disable_proxy failed: err=%v res=%+v", err, quarRes)
	}

	if !pool.GetConfig().Enabled {
		t.Fatalf("expected Proxy Pool to stay Enabled when last proxy fails during agent failover")
	}
	if !s.m.IsProxyPoolFailClosed() || !s.m.HasOutboundProxy() {
		t.Fatalf("expected fail-closed outbound proxy guard active")
	}

	// Active chat run must be immediately cancelled with AbortPausedByProxy!
	if !errors.Is(context.Cause(chatCtx), agent.AbortPausedByProxy) {
		t.Fatalf("expected active chat to be aborted with AbortPausedByProxy, got %v", context.Cause(chatCtx))
	}

	// Outbound external HTTP requests MUST fail-closed with 503 instead of dialing direct!
	fwdAddr := s.m.OutboundProxyAddr()
	if !strings.HasPrefix(fwdAddr, "http://127.0.0.1:") {
		t.Fatalf("expected non-empty OutboundProxyAddr in fail-closed state, got %q", fwdAddr)
	}
	spURL, _ := url.Parse(fwdAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(spURL)}}
	resp, err := client.Get("http://external.target.example/secret")
	if err != nil {
		t.Fatalf("proxy forwarder transport error: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "Fail-Closed Proxy Guard") {
		t.Fatalf("expected 503 Fail-Closed Proxy Guard, got status=%d body=%q", resp.StatusCode, string(body))
	}

	// check_proxy_status must report proxy_pool_exhausted=true and STOP WORK instruction.
	stRes, _ := s.toolCheckProxyStatus().Call(context.Background(), json.RawMessage(`{}`), nil)
	out := stRes.Content[0].Text
	if !strings.Contains(out, `"proxy_pool_exhausted":true`) || !strings.Contains(out, "STOP WORK IMMEDIATELY") {
		t.Fatalf("expected check_proxy_status to report fail-closed stop instruction, got %s", out)
	}
}

