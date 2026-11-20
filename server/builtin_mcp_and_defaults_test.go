package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestPlatformDefaultsInterceptRulesBuiltInMCPsAndNotificationDiscovery(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)

	// 1. Verify recommended platform & behavioral settings are enabled out of the box
	payload := s.settingsPayload()
	for _, key := range []string{
		"agent_traffic_binding",
		"browser_screenshot_enabled",
		"browser_screenshot_timestamp_enabled",
		"opsec_enabled",
		"task_intelligence_enabled",
		db.SettingTaskAutoTitle,
		db.SettingChatAutoTitle,
		db.SettingCredentialAgent,
		db.SettingCredentialTraffic,
	} {
		if payload[key] != true {
			t.Fatalf("expected setting %q enabled by default, got %v", key, payload[key])
		}
	}

	// 2. Verify intercept_default_rules_v5 disabled non-host target rules while keeping Host OS rules enabled
	rules, err := s.m.pg.ListInterceptRules()
	if err != nil {
		t.Fatalf("ListInterceptRules: %v", err)
	}
	byName := map[string]bool{}
	for _, r := range rules {
		byName[r.Name] = r.Enabled
	}
	for _, shouldBeOff := range []string{
		"[Built-in] curl / wget HTTP DELETE request",
		"[Built-in] Python HTTP client DELETE (requests/httpx/aiohttp)",
		"[Built-in] HTTP DELETE method in script (JS/general)",
		"[Built-in] SQL DROP DATABASE / TABLE / SCHEMA",
		"[Built-in] SQL TRUNCATE",
		"[Built-in] MongoDB drop / dropDatabase",
		"[Built-in] Redis FLUSHALL / FLUSHDB",
	} {
		if byName[shouldBeOff] {
			t.Fatalf("expected non-host rule %q disabled by default, got enabled=true", shouldBeOff)
		}
	}
	for _, shouldBeOn := range []string{
		"[Built-in] Format disk mkfs",
		"[Built-in] Fork bomb",
		"[Built-in] Destructive system commands",
	} {
		if !byName[shouldBeOn] {
			t.Fatalf("expected Host OS safety rule %q enabled by default, got enabled=false", shouldBeOn)
		}
	}

	// 3. Verify built-in Python STDIO MCP servers (vuln_intel, recon_osint, web_sec_analyzer)
	//    connect over stdio JSON-RPC, discover all tools, and execute jwt_decode_and_audit!
	mcps, err := s.m.pg.ListMCP()
	if err != nil {
		t.Fatalf("ListMCP: %v", err)
	}
	mcpMap := map[string]*db.MCPServer{}
	for _, m := range mcps {
		mcpMap[m.Name] = m
	}
	for _, wantName := range []string{"vuln_intel", "recon_osint", "web_sec_analyzer"} {
		srv := mcpMap[wantName]
		if srv == nil || !srv.Enabled {
			t.Fatalf("expected built-in MCP %q seeded & enabled, got %+v", wantName, srv)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if derr := s.discoverAndCacheMCP(ctx, srv); derr != nil {
			cancel()
			t.Fatalf("discoverAndCacheMCP(%s) failed: %v", wantName, derr)
		}
		cancel()
	}

	// Live call to web_sec_analyzer -> jwt_decode_and_audit (alg:none detection)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cl, err := connectMCP(ctx, mcpMap["web_sec_analyzer"])
	if err != nil {
		t.Fatalf("connectMCP(web_sec_analyzer): %v", err)
	}
	defer cl.Close()
	tools, err := cl.Tools(ctx)
	if err != nil || len(tools) != 4 {
		t.Fatalf("expected 4 tools from web_sec_analyzer, got len=%d err=%v", len(tools), err)
	}
	for _, tl := range tools {
		if strings.HasSuffix(tl.Name(), "jwt_decode_and_audit") {
			// eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9. => {"alg":"none"}.{"sub":"admin"}.
			res, cerr := tl.Call(ctx, json.RawMessage(`{"token":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}`), nil)
			if cerr != nil || res.IsError || !strings.Contains(res.Flatten(), "CRITICAL: alg is 'none'") {
				t.Fatalf("jwt_decode_and_audit unexpected output: err=%v res=%s", cerr, res.Flatten())
			}
		}
	}

	// 4. Verify Patch Monitor built-in watch feeds >= 26, add_patch_watch_feed works,
	//    and EnrollNotificationCandidates adds passive notify_candidate targets with security.txt!
	sources, err := s.patchMon.GetAllSources()
	if err != nil || len(sources) < 26 {
		t.Fatalf("expected >= 26 built-in watch feeds (including Hacker News), got %d (err=%v)", len(sources), err)
	}

	mockSite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Contact: mailto:secops@example-notify.test\n"))
			return
		}
		w.Header().Set("Server", "Apache/2.4.58")
		w.Header().Set("X-Powered-By", "PHP/8.2.15")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<rss><channel><item><title>CVE-2025-99999 Advisory</title><description>Test RSS</description></item></channel></rss>"))
	}))
	defer mockSite.Close()

	feedIn, _ := json.Marshal(map[string]any{
		"name":             "Custom HN Security Feed Test",
		"url":              mockSite.URL + "/rss.xml",
		"source_type":      "rss",
		"poll_immediately": true,
	})
	feedRes, err := s.toolAddPatchWatchFeed().Call(context.Background(), feedIn, nil)
	if err != nil || feedRes.IsError || !strings.Contains(feedRes.Flatten(), "Custom HN Security Feed Test") {
		t.Fatalf("add_patch_watch_feed failed: err=%v res=%s", err, feedRes.Flatten())
	}

	cands, err := s.patchMon.EnrollNotificationCandidates("CodeIgniter", "CVE-2024-4577", []string{mockSite.URL})
	if err != nil || len(cands) != 1 || cands[0].DisclosureContact != "mailto:secops@example-notify.test" {
		t.Fatalf("EnrollNotificationCandidates unexpected: err=%v cands=%+v", err, cands)
	}

	// 5. Verify Turnstile single-key partial submission is rejected cleanly
	r := request("PUT", "/api/settings", `{"turnstile_site_key":"0x4AAAAAA_site_only"}`)
	if r.Code != 400 {
		t.Fatalf("expected 400 when setting Turnstile site_key without secret_key, got %d: %s", r.Code, r.Body.String())
	}
}
