package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/behemoth/db"
	proxyv2 "github.com/Autumn-27/behemoth/server/proxy/v2"
)

func TestAllForensicAndMCPToolsRouteThroughEnabledProxyWithoutServerIPLeak(t *testing.T) {
	// Spin up an upstream proxy that intercepts all external HTTP requests and stamps proof
	// so any direct unproxied connection to external.target.invalid would fail DNS resolution!
	var upstreamProxyHits atomic.Int64
	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamProxyHits.Add(1)
		w.Header().Set("Server", "ProxiedTarget/1.0")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "security.txt") {
			_, _ = io.WriteString(w, "Contact: mailto:sec@proxied-only.invalid\n")
			return
		}
		_, _ = io.WriteString(w, "<!doctype html><html><body>Served strictly via proxy</body></html>")
	}))
	defer upstreamProxy.Close()

	pu, _ := url.Parse(upstreamProxy.URL)
	host, portStr, _ := net.SplitHostPort(pu.Host)

	s, _, _ := trafficEvidenceServer(t)

	pool := proxyv2.NewPool(nil)
	ppV2 = &proxyPoolV2{
		Pool:    pool,
		Handler: proxyv2.NewHandler(pool),
	}
	pool.SetSyncHook(func(proxies []proxyv2.ProxyInfo, activeID string, cfg *proxyv2.ProxyPoolConfig) {
		s.syncProxyPoolV2ToV1(proxies, activeID, cfg)
	})

	// Import & activate the proxy in Proxy Pool v2
	if _, err := pool.ImportProxies(host+":"+portStr, proxyv2.ProxyTypeHTTP); err != nil {
		t.Fatal(err)
	}
	pxList := pool.GetProxies()
	if err := pool.ActivateProxy(pxList[0].ID); err != nil {
		t.Fatal(err)
	}
	s.syncProxyPoolNow()

	if !s.m.HasOutboundProxy() || !strings.HasPrefix(s.m.OutboundProxyAddr(), "http://127.0.0.1:") {
		t.Fatalf("expected OutboundProxyAddr active, got HasOutbound=%v addr=%q", s.m.HasOutboundProxy(), s.m.OutboundProxyAddr())
	}

	// 1. Forensic tool detect_deception_and_honeypot against a non-resolvable external host
	//    MUST succeed ONLY because it routes through the enabled proxy (direct would fail DNS)!
	hitsBefore := upstreamProxyHits.Load()
	decIn, _ := json.Marshal(map[string]any{"target_url": "http://external-only.proxied.invalid"})
	decRes, err := s.toolDetectDeceptionAndHoneypot().Call(context.Background(), decIn, nil)
	if err != nil || decRes.IsError {
		t.Fatalf("detect_deception_and_honeypot bypassed proxy (failed on external host): err=%v res=%s", err, decRes.Flatten())
	}
	if upstreamProxyHits.Load() <= hitsBefore {
		t.Fatalf("expected detect_deception_and_honeypot to route through upstream proxy")
	}

	// 2. Spawned STDIO MCP server (web_sec_analyzer -> http_security_headers_audit)
	//    MUST inherit HTTP_PROXY/HTTPS_PROXY via connectMCP and route through the proxy!
	mcps, err := s.m.pg.ListMCP()
	if err != nil {
		t.Fatalf("ListMCP: %v", err)
	}
	var webSecMCP, reconMCP *db.MCPServer
	for _, m := range mcps {
		if m.Name == "web_sec_analyzer" {
			webSecMCP = m
		}
		if m.Name == "recon_osint" {
			reconMCP = m
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hitsBeforeMCP := upstreamProxyHits.Load()
	cl, err := connectMCP(ctx, webSecMCP, s.m.OutboundProxyAddr())
	if err != nil {
		t.Fatalf("connectMCP(web_sec_analyzer): %v", err)
	}
	defer cl.Close()
	mcpTools, err := cl.Tools(ctx)
	if err != nil {
		t.Fatalf("web_sec_analyzer Tools(): %v", err)
	}
	for _, tl := range mcpTools {
		if strings.HasSuffix(tl.Name(), "http_security_headers_audit") {
			res, cerr := tl.Call(ctx, json.RawMessage(`{"url":"http://external-mcp-target.proxied.invalid/"}`), nil)
			if cerr != nil || res.IsError || !strings.Contains(res.Flatten(), "ProxiedTarget/1.0") {
				t.Fatalf("MCP http_security_headers_audit did NOT route through proxy: err=%v res=%s", cerr, res.Flatten())
			}
		}
	}
	if upstreamProxyHits.Load() <= hitsBeforeMCP {
		t.Fatalf("expected MCP web_sec_analyzer to exit through upstream proxy")
	}

	// 3. Spawned STDIO MCP server (recon_osint -> security_txt_contacts) also routes via proxy!
	hitsBeforeRecon := upstreamProxyHits.Load()
	cl2, err := connectMCP(ctx, reconMCP, s.m.OutboundProxyAddr())
	if err != nil {
		t.Fatalf("connectMCP(recon_osint): %v", err)
	}
	defer cl2.Close()
	reconTools, _ := cl2.Tools(ctx)
	for _, tl := range reconTools {
		if strings.HasSuffix(tl.Name(), "security_txt_contacts") {
			res, cerr := tl.Call(ctx, json.RawMessage(`{"domain_or_url":"http://proxied-only.invalid"}`), nil)
			if cerr != nil || res.IsError || !strings.Contains(res.Flatten(), "sec@proxied-only.invalid") {
				t.Fatalf("MCP security_txt_contacts did NOT route through proxy: err=%v res=%s", cerr, res.Flatten())
			}
		}
	}
	if upstreamProxyHits.Load() <= hitsBeforeRecon {
		t.Fatalf("expected MCP recon_osint to exit through upstream proxy")
	}

	// 4. PatchMonitor EnrollNotificationCandidates also routes via proxy!
	hitsBeforePatch := upstreamProxyHits.Load()
	cands, err := s.patchMon.EnrollNotificationCandidates("Nginx", "CVE-2025-0001", []string{"http://proxied-only.invalid"})
	if err != nil || len(cands) != 1 || !strings.Contains(cands[0].DisclosureContact, "sec@proxied-only.invalid") {
		t.Fatalf("EnrollNotificationCandidates bypassed proxy: err=%v cands=%+v", err, cands)
	}
	if upstreamProxyHits.Load() <= hitsBeforePatch {
		t.Fatalf("expected EnrollNotificationCandidates to exit through upstream proxy")
	}
}
