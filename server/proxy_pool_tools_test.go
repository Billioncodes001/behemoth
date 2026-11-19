package server

import (
	"context"
	"encoding/json"
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

	// Session starts BEFORE any proxy is imported — SessionProxyAddr already points to local dynamic forwarder!
	sessionProxy := s.m.SessionProxyAddr()
	if !strings.HasPrefix(sessionProxy, "http://127.0.0.1:") {
		t.Fatalf("expected stable local session forwarder, got %q", sessionProxy)
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
}
