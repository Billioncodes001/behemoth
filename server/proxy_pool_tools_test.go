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

	"github.com/Autumn-27/behemoth/agent"
	proxyv2 "github.com/Autumn-27/behemoth/server/proxy/v2"
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
	// SessionProxyAddr MUST be empty ("") and check_proxy_status MUST report proxy_enabled=false
	// with the hard no-direct guard active (default policy blocks direct egress)!
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
	if chkPayload["proxy_enabled"] != false || chkPayload["effective_routing_mode"] != "no_outbound_direct_blocked" {
		t.Fatalf("expected proxy_enabled=false & no_outbound_direct_blocked before import, got %+v", chkPayload)
	}
	if policy, _ := chkPayload["auth_page_policy"].(string); !strings.Contains(policy, "does not apply") {
		t.Fatalf("expected direct-mode auth_page_policy to be a no-op notice, got %q", policy)
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

	// Verify disabling Proxy Pool engages the no-direct guard (routing blocked, never direct),
	// and re-enabling + configuring restores pool routing immediately.
	disRes, err := s.toolManageProxyPool().Call(context.Background(), json.RawMessage(`{"action":"disable"}`), nil)
	if err != nil || disRes.IsError {
		t.Fatalf("manage_proxy_pool disable failed: err=%v res=%+v", err, disRes)
	}
	stRes, _ := s.toolGetProxyPoolStatus().Call(context.Background(), json.RawMessage(`{}`), nil)
	if !strings.Contains(stRes.Content[0].Text, `"effective_routing_mode":"no_outbound_direct_blocked"`) {
		t.Fatalf("expected blocked routing when pool disabled, got %s", stRes.Content[0].Text)
	}

	enRes, err := s.toolManageProxyPool().Call(context.Background(), json.RawMessage(`{"action":"enable","rotation_strategy":"least_used","session_sticky":false,"rotation_interval_seconds":15}`), nil)
	if err != nil || enRes.IsError {
		t.Fatalf("manage_proxy_pool enable/configure failed: err=%v res=%+v", err, enRes)
	}
	stRes2, _ := s.toolGetProxyPoolStatus().Call(context.Background(), json.RawMessage(`{}`), nil)
	if !strings.Contains(stRes2.Content[0].Text, `"effective_routing_mode":"proxy_pool"`) {
		t.Fatalf("expected proxy_pool routing restored after re-enable, got %s", stRes2.Content[0].Text)
	}
	// An active proxy must surface the auth-page throttle policy to the agent.
	if !strings.Contains(stRes2.Content[0].Text, "AUTH-PAGE THROTTLE") {
		t.Fatalf("expected proxy-active auth_page_policy, got %s", stRes2.Content[0].Text)
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

func TestTorCoexistenceModesScraperToolsAndSkillAutoDiscovery(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	ctx := context.Background()

	// 1. Verify proxy_harvester built-in agent is seeded and newly shipped skills
	//    (captcha-solving, cloud-and-container-audit, proxy-harvesting) are auto-visible!
	s.skillDir = filepath.Join("..", "skills")
	s.syncDiscoveredSkillsVisibility()

	harvester, err := s.m.pg.GetAgentByKey("proxy_harvester")
	if err != nil || harvester == nil {
		t.Fatalf("expected proxy_harvester built-in agent to be seeded, got err=%v", err)
	}
	autoAg, _ := s.m.pg.GetAgentByKey("auto")
	autoSkills, _ := s.m.pg.AgentSkillNames(autoAg.ID)
	skillSet := map[string]bool{}
	for _, sk := range autoSkills {
		skillSet[sk] = true
	}
	for _, wantSkill := range []string{"captcha-solving", "cloud-and-container-audit", "deception-and-honeypot-detection", "proxy-harvesting"} {
		if !skillSet[wantSkill] {
			t.Fatalf("expected skill %q to be auto-visible to auto agent, got %v", wantSkill, autoSkills)
		}
	}

	// 2. Verify Tor Exclusive suspend/restore coexistence with existing non-Tor pool proxies
	pool := proxyv2.NewPool(nil)
	if _, err := pool.ImportProxies("198.51.100.10:8080:u:p\n198.51.100.11:8080:u:p", proxyv2.ProxyTypeHTTP); err != nil {
		t.Fatal(err)
	}
	initial := pool.GetProxies()
	if err := pool.ActivateProxy(initial[0].ID); err != nil {
		t.Fatal(err)
	}
	suspended, err := pool.SuspendNonPrefixProxies("tor-circuit-")
	if err != nil || len(suspended) != 2 {
		t.Fatalf("expected 2 non-Tor proxies suspended in Exclusive Tor mode, got %d (err=%v)", len(suspended), err)
	}
	torEntries := buildTorCircuitEntries(19050, 3, "nonce-1")
	if err := pool.ReplaceManagedPrefixProxies("tor-circuit-", torEntries, true); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pool.GetStats().ActiveProxyID, "tor-circuit-") {
		t.Fatalf("expected active proxy to switch immediately to Tor circuit, got %q", pool.GetStats().ActiveProxyID)
	}
	// Restore non-Tor proxies and remove Tor circuits -> original proxies active again!
	if err := pool.RestoreProxyIDs(suspended); err != nil {
		t.Fatal(err)
	}
	if err := pool.ReplaceManagedPrefixProxies("tor-circuit-", nil, false); err != nil {
		t.Fatal(err)
	}
	if pool.GetStats().ActiveProxyID == "" || strings.HasPrefix(pool.GetStats().ActiveProxyID, "tor-circuit-") {
		t.Fatalf("expected non-Tor proxy restored after disabling Tor, got %q", pool.GetStats().ActiveProxyID)
	}

	// 3. Verify Online Proxy Scraper candidate extractor & custom feed CRUD tools
	cands := extractProxiesFromBody("socks5://8.8.4.4:1080\n1.1.1.1:8080\n127.0.0.1:9050\n10.0.0.5:3128", "http", "test-src", true)
	if len(cands) != 2 || cands[0].Protocol != "socks5" || cands[1].Host != "1.1.1.1" {
		t.Fatalf("expected private/loopback filtered and 2 public proxies extracted, got %+v", cands)
	}

	addRes, err := s.toolAddProxyScrapeSource().Call(ctx, json.RawMessage(`{"name":"AI Discovered SOCKS5","url":"https://example.org/proxies.txt","protocol":"socks5","priority":true,"test_immediately":false}`), nil)
	if err != nil || addRes.IsError || !strings.Contains(addRes.Flatten(), `"added":true`) {
		t.Fatalf("add_proxy_scrape_source failed: err=%v out=%s", err, addRes.Flatten())
	}
	var addedPayload struct {
		Source ProxyScrapeSource `json:"source"`
	}
	_ = json.Unmarshal([]byte(addRes.Flatten()), &addedPayload)

	listRes, err := s.toolListProxyScrapeSources().Call(ctx, json.RawMessage(`{}`), nil)
	if err != nil || listRes.IsError || !strings.Contains(listRes.Flatten(), "AI Discovered SOCKS5") {
		t.Fatalf("list_proxy_scrape_sources missing added source: err=%v out=%s", err, listRes.Flatten())
	}

	remRes, err := s.toolRemoveProxyScrapeSource().Call(ctx, json.RawMessage(`{"source_id":"`+addedPayload.Source.ID+`"}`), nil)
	if err != nil || remRes.IsError || !strings.Contains(remRes.Flatten(), `"removed":true`) {
		t.Fatalf("remove_proxy_scrape_source failed: err=%v out=%s", err, remRes.Flatten())
	}
}

func TestExclusiveTorAutoDisablesPoolAndPoolEnableShutsDownExclusiveTor(t *testing.T) {
	poolProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "via-pool-proxy")
	}))
	defer poolProxy.Close()
	torMockProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "via-exclusive-tor")
	}))
	defer torMockProxy.Close()

	pu, _ := url.Parse(poolProxy.URL)
	pHost, pPort, _ := net.SplitHostPort(pu.Host)

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

	// 1. Import & activate a pool proxy; verify agent WebFetchProxyAddr routes via pool!
	if _, err := pool.ImportProxies(pHost+":"+pPort, proxyv2.ProxyTypeHTTP); err != nil {
		t.Fatal(err)
	}
	pxList := pool.GetProxies()
	if err := pool.ActivateProxy(pxList[0].ID); err != nil {
		t.Fatal(err)
	}
	s.syncProxyPoolNow()

	// Pre-capture WebFetchProxyAddr (simulating an already-running agent session!)
	liveForwarderURL, _ := url.Parse(s.m.WebFetchProxyAddr())
	runningAgentClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(liveForwarderURL)}}

	resp1, err := runningAgentClient.Get("http://external.target.example/step1")
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if string(b1) != "via-pool-proxy" {
		t.Fatalf("expected initial request via pool proxy, got %q", string(b1))
	}

	// 2. Activate Exclusive Tor: Proxy Pool auto-disables (while pool entry stays active/untouched),
	//    and the ALREADY-RUNNING agent client immediately switches to Exclusive Tor!
	poolCfg := pool.GetConfig()
	poolCfg.Enabled = false
	_ = pool.UpdateConfig(poolCfg)
	s.syncProxyPoolNow()
	s.m.SetExclusiveTor(true, []string{torMockProxy.URL})

	if pool.GetConfig().Enabled {
		t.Fatalf("expected Proxy Pool to be auto-disabled while Exclusive Tor is active")
	}
	if !pool.GetProxies()[0].Active {
		t.Fatalf("expected pool entry to remain untouched/active in table while pool itself is disabled")
	}
	stRes, _ := s.toolCheckProxyStatus().Call(context.Background(), json.RawMessage(`{}`), nil)
	if !strings.Contains(stRes.Flatten(), `"effective_routing_mode":"exclusive_tor"`) {
		t.Fatalf("expected check_proxy_status to report exclusive_tor, got %s", stRes.Flatten())
	}

	resp2, err := runningAgentClient.Get("http://external.target.example/step2")
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if string(b2) != "via-exclusive-tor" {
		t.Fatalf("expected running agent to immediately switch to Exclusive Tor mid-run, got %q", string(b2))
	}

	// 3. Switch Proxy Pool back ON while Exclusive Tor is active -> Exclusive Tor MUST auto-shutdown,
	//    and the running agent immediately switches back to the Pool proxy!
	if err := pool.ActivateProxy(pxList[0].ID); err != nil {
		t.Fatal(err)
	}
	s.syncProxyPoolNow()

	if s.isExclusiveTorActive() {
		t.Fatalf("expected Exclusive Tor to auto-shutdown as soon as Proxy Pool was switched ON")
	}
	resp3, err := runningAgentClient.Get("http://external.target.example/step3")
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	if string(b3) != "via-pool-proxy" {
		t.Fatalf("expected running agent to switch back to pool proxy after Exclusive Tor auto-shutdown, got %q", string(b3))
	}
}
