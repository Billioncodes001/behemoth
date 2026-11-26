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

	"github.com/Autumn-27/behemoth/agent/payloads"
	"github.com/Autumn-27/behemoth/agent/research"
	"github.com/Autumn-27/behemoth/db"
	"github.com/Autumn-27/behemoth/server/patchmonitor"
	"github.com/Autumn-27/behemoth/server/search"
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

	vulns, err := s.patchMon.GetVulnerabilities(status, limit)
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

func (s *Server) handlePatchMonitorAutoMatchTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}
	matched, err := s.patchMon.AutoMatchAuthorizedTargets(nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "auto-match failed: "+err.Error())
		return
	}
	added := 0
	for _, m := range matched {
		if m.NewlyAdded {
			added++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matched": len(matched),
		"added":   added,
		"items":   matched,
	})
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
		AutoTarget   *bool  `json:"auto_target"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	autoPayload := true
	if req.AutoPayload != nil {
		autoPayload = *req.AutoPayload
	}
	if req.AutoTarget != nil {
		s.patchMon.SetAutoTarget(*req.AutoTarget)
	}
	s.patchMon.Configure(req.LLMProfileID, autoPayload)

	if s.patchMon.IsRunning() {
		json.NewEncoder(w).Encode(s.patchMon.StatusSnapshot())
		return
	}

	s.patchMon.Start(r.Context())
	log.Printf("[api] Patch monitor started (profile=%v, auto_payload=%v, auto_target=%v)", req.LLMProfileID, autoPayload, s.patchMon.AutoTargetEnabled())
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
		AutoTarget   *bool  `json:"auto_target"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.AutoTarget != nil {
		s.patchMon.SetAutoTarget(*req.AutoTarget)
	}
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
		Type   string          `json:"type"`   // "cc_skimmer", "cookie_exfil", "crypto_swap_dom", "crypto_swap_clipboard", "screen_exfil"
		Config json.RawMessage `json:"config"` // Type-specific config
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
		"Patch Monitor Watch Cycle triggered (%d security advisory feeds polled across vendor PSIRTs, NVD, CISA KEV, Hacker News Security, ProjectDiscovery, PortSwigger, ZDI, BleepingComputer, Packet Storm, and Exploit-DB).\n\n"+
			"Tracked High/Critical Security Patches & CVEs:\n%s\n\n"+
			"Execute your autonomous Patch Watch, Feed Expansion, Scope Matching & Responsible Notification Discovery workflow now:\n"+
			"1. Call `check_proxy_status` first to check if Proxy Pool, Tor, or Global Proxy is enabled (NEVER connect directly when `proxy_enabled` is false — direct egress is blocked by policy: activate scraped proxies or call `scrape_online_proxies` / `manage_proxy_pool(action='enable_tor')`, or stop and notify the operator; rotate via `manage_proxy_pool` if a proxy is degraded).\n"+
			"2. Call `check_patch_feeds` to review the latest vulnerabilities and `generate_vuln_exploit` on the highest-priority vulnerability ID to synthesize a PoC exploit.\n"+
			"3. Proactively expand watch coverage: if any major vendor, framework, or community security feed (e.g., Hacker News topic RSS, vendor PSIRT RSS/Atom, GitHub Releases Atom) relevant to the discovered technologies is not yet in `check_patch_feeds`, register and poll it via `add_patch_watch_feed`.\n"+
			"4. Call `match_vuln_targets` to correlate the affected technology/software against BEHEMOTH's registered authorized Assets & Scope inventory (`assets` & `exploit_targets`). Verify in-scope assets safely and update via `update_exploit_target_status`.\n"+
			"5. Call `discover_affected_sites_for_notification` for the primary vulnerable technology/product so publicly indexed websites using that technology (along with their `/.well-known/security.txt` contacts) are enrolled into the Targets list (`notify_candidate`) for responsible vulnerability notification (never execute active exploits against out-of-scope notification candidates).\n"+
			"6. Output a concise intelligence briefing summarizing watched advisories, newly added watch feeds, generated PoCs, matched in-scope targets, and discovered notification candidates.",
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
		s.toolSearchPatchArsenal(),
		s.toolSaveVerifiedExploitToPatchMonitor(),
		s.toolSyncNucleiTemplates(),
		s.toolGeneratePayload(),
		s.toolCheckPatchFeeds(),
		s.toolAddPatchWatchFeed(),
		s.toolGenerateVulnExploit(),
		s.toolMatchVulnTargets(),
		s.toolDiscoverAffectedSitesForNotification(),
		s.toolUpdateExploitTargetStatus(),
		s.toolSearchIOSExploits(),
		s.toolMultiEngineSearch(),
		s.toolExploitSearch(),
	}
}

// toolSyncNucleiTemplates regenerates the private nuclei template repository from
// verified Patch Monitor exploits (self-improving scanner templates).
func (s *Server) toolSyncNucleiTemplates() actool.CoreTool {
	return wrTool("sync_nuclei_templates",
		"Regenerate BEHEMOTH's private nuclei template repository from verified Patch Monitor exploits (writes nuclei YAML templates to <data>/nuclei-templates/behemoth and prunes stale ones). Subsequent nuclei-scan runs automatically include these templates, making the scanner self-improving as more exploits are verified.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			if s.patchMon == nil {
				return actool.Errorf("patch monitor is not initialized"), nil
			}
			changes, err := s.patchMon.SyncNucleiTemplates()
			if err != nil {
				return actool.Errorf(fmt.Sprintf("nuclei template sync failed: %v", err)), nil
			}
			return jsonResult(map[string]any{
				"ok":            true,
				"changes":       changes,
				"templates_dir": s.patchMon.NucleiTemplatesDir(),
				"auto_injected": s.customNucleiTemplateDir() != "",
			})
		})
}

func (s *Server) toolSearchPatchArsenal() actool.CoreTool {
	return roTool("search_patch_arsenal",
		"Search BEHEMOTH Patch Monitor's existing vulnerabilities, auto-generated PoC exploits, and verified client-side payloads by CVE ID, library/technology name (e.g. 'jQuery', 'Bootstrap', 'PHP', 'WordPress', 'OpenSSH'), or vulnerability class ('XSS', 'SQLi', 'RCE', 'LFI', 'cookie_exfil'). ALWAYS call this FIRST when you detect an outdated library, CVE, or vulnerability class on a target so you can reuse existing exploits/payloads before building one from scratch!",
		objSchema(map[string]any{
			"query": strParam("CVE ID, technology/library name, or vulnerability class (e.g. 'jQuery', 'CVE-2020-11022', 'XSS', 'Bootstrap', 'SQLi')"),
			"limit": map[string]any{"type": "integer", "description": "Max items to return (default 15)"},
		}, "query"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s.m == nil || s.m.pg == nil {
				return actool.Errorf("database is not initialized"), nil
			}
			var a struct {
				Query string `json:"query"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			gen := patchmonitor.NewExploitGenerator(s.m.pg.DB)
			vulns, exploits, err := gen.SearchArsenal(a.Query, a.Limit)
			if err != nil {
				return actool.Errorf("search_patch_arsenal failed: " + err.Error()), nil
			}
			note := "Reuse any matching exploit/payload code directly against the target. If no ready PoC matches this exact version/sink, craft and verify a working PoC yourself, then persist it back via save_verified_exploit_to_patch_monitor!"
			return jsonResult(map[string]any{
				"query":             a.Query,
				"matched_vulns":     len(vulns),
				"matched_exploits":  len(exploits),
				"vulnerabilities":   vulns,
				"exploits_payloads": exploits,
				"guidance":          note,
			})
		})
}

func (s *Server) toolSaveVerifiedExploitToPatchMonitor() actool.CoreTool {
	return wrTool("save_verified_exploit_to_patch_monitor",
		"Persist a newly synthesized and verified working PoC exploit or payload (along with its CVE / affected library / version metadata) into BEHEMOTH Patch Monitor (`patch_vulnerabilities` + `generated_exploits` with status='verified_working') so future scans and agents can immediately reuse it.",
		objSchema(map[string]any{
			"title":             strParam("Vulnerability & PoC title (e.g. 'jQuery < 3.5.0 htmlPrefilter Self-Closing Tag XSS PoC')"),
			"code":              strParam("Complete, self-contained, verified working PoC exploit or payload code"),
			"language":          strParam("Code language: javascript | python | bash | http | html"),
			"exploit_type":      strParam("Category: xss | sqli | rce | lfi | ssrf | auth_bypass | payload:cookie_exfil | verified_poc"),
			"cve_id":            strParam("Optional CVE ID (e.g. 'CVE-2020-11022')"),
			"severity":          strParam("Severity: critical | high | medium | low"),
			"cvss_score":        map[string]any{"type": "number", "description": "Optional CVSS score (0.0 - 10.0)"},
			"description":       strParam("Technical summary of root cause, sink/trigger conditions, and impact"),
			"affected_software": strParam("Affected library, framework, or product (e.g. 'jQuery', 'Bootstrap', 'CodeIgniter')"),
			"affected_versions": strParam("Affected version range (e.g. 'jQuery 1.2 - 3.4.1')"),
			"patched_version":   strParam("Patched version (e.g. '3.5.0')"),
			"verified_target":   strParam("Optional target URL/origin where this PoC was verified working"),
			"verified_output":   strParam("Optional concise proof output from the live verification run"),
		}, "title", "code"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s.m == nil || s.m.pg == nil {
				return actool.Errorf("database is not initialized"), nil
			}
			var a struct {
				Title            string  `json:"title"`
				Code             string  `json:"code"`
				Language         string  `json:"language"`
				ExploitType      string  `json:"exploit_type"`
				CVEID            string  `json:"cve_id"`
				Severity         string  `json:"severity"`
				CVSSScore        float64 `json:"cvss_score"`
				Description      string  `json:"description"`
				AffectedSoftware string  `json:"affected_software"`
				AffectedVersions string  `json:"affected_versions"`
				PatchedVersion   string  `json:"patched_version"`
				VerifiedTarget   string  `json:"verified_target"`
				VerifiedOutput   string  `json:"verified_output"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			gen := patchmonitor.NewExploitGenerator(s.m.pg.DB)
			vulnID, expID, err := gen.SaveVerifiedExploit(patchmonitor.VerifiedExploitInput{
				CVEID:            a.CVEID,
				Title:            a.Title,
				Description:      a.Description,
				Severity:         a.Severity,
				CVSSScore:        a.CVSSScore,
				AffectedSoftware: a.AffectedSoftware,
				AffectedVersions: a.AffectedVersions,
				PatchedVersion:   a.PatchedVersion,
				ExploitType:      a.ExploitType,
				Language:         a.Language,
				Code:             a.Code,
				Confidence:       0.95,
				VerifiedTarget:   a.VerifiedTarget,
				VerifiedOutput:   a.VerifiedOutput,
			})
			if err != nil {
				return actool.Errorf("failed to save verified exploit: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"ok":         true,
				"vuln_id":    vulnID,
				"exploit_id": expID,
				"status":     "verified_working",
				"message":    fmt.Sprintf("Saved verified working exploit #%d (vuln #%d) into Patch Monitor (/function/patch-monitor).", expID, vulnID),
			})
		})
}

func (s *Server) toolAddPatchWatchFeed() actool.CoreTool {
	return wrTool("add_patch_watch_feed",
		"Register a new security vulnerability/advisory watch feed (RSS, Atom, Hacker News hnrss.org query feed, GitHub releases.atom, or JSON bulletin) in Patch Monitor -> Watch Feeds and immediately poll it for advisories.",
		objSchema(map[string]any{
			"name":                   strParam("Descriptive feed name (e.g. 'Hacker News — Laravel & PHP Security', 'Apache Tomcat Announcements')"),
			"url":                    strParam("Feed URL (RSS/Atom/JSON, e.g. 'https://hnrss.org/newest?q=Laravel+CVE' or 'https://github.com/org/repo/releases.atom')"),
			"source_type":            strParam("Feed parser type: rss (default) | atom | github | nvd | cisa_kev"),
			"check_interval_minutes": map[string]any{"type": "integer", "description": "Polling interval in minutes (default 30)"},
			"poll_immediately":       map[string]any{"type": "boolean", "description": "Immediately fetch & parse this feed after adding (default true)"},
		}, "name", "url"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s.patchMon == nil {
				return actool.Errorf("patch monitor is not initialized"), nil
			}
			var a struct {
				Name                 string `json:"name"`
				URL                  string `json:"url"`
				SourceType           string `json:"source_type"`
				CheckIntervalMinutes int    `json:"check_interval_minutes"`
				PollImmediately      *bool  `json:"poll_immediately"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			if strings.TrimSpace(a.Name) == "" || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.URL)), "http") {
				return actool.Errorf("valid name and http(s) url are required"), nil
			}
			if a.CheckIntervalMinutes <= 0 {
				a.CheckIntervalMinutes = 30
			}
			stype := strings.ToLower(strings.TrimSpace(a.SourceType))
			if stype == "" {
				if strings.HasSuffix(strings.ToLower(a.URL), ".atom") {
					stype = "atom"
				} else {
					stype = "rss"
				}
			}
			id, err := s.patchMon.AddSource(patchmonitor.PatchSource{
				Name:                 a.Name,
				URL:                  a.URL,
				SourceType:           stype,
				CheckIntervalMinutes: a.CheckIntervalMinutes,
				Enabled:              true,
			})
			if err != nil {
				return actool.Errorf("failed to add watch feed: " + err.Error()), nil
			}
			pollNow := a.PollImmediately == nil || *a.PollImmediately
			var newVulns []patchmonitor.Vulnerability
			if pollNow {
				newVulns, _ = s.patchMon.PollSourceByID(id)
			}
			return jsonResult(map[string]any{
				"source_id":          id,
				"name":               a.Name,
				"url":                a.URL,
				"source_type":        stype,
				"polled_immediately": pollNow,
				"new_vulns_ingested": len(newVulns),
				"new_vulns":          newVulns,
			})
		})
}

func (s *Server) toolDiscoverAffectedSitesForNotification() actool.CoreTool {
	return wrTool("discover_affected_sites_for_notification",
		"When a vulnerability is discovered in a platform or technology (e.g. WordPress plugin, CodeIgniter, GitLab, TeamCity, Next.js, Fortinet), passively search public indexes for websites running that technology, look up their RFC 9116 /.well-known/security.txt disclosure contacts, and enroll them into Patch Monitor -> Targets (status='notify_candidate') so the operator can responsibly notify them. Never runs active exploits on notification candidates.",
		objSchema(map[string]any{
			"technology":   strParam("Affected platform, framework, CMS, or server technology (e.g. 'CodeIgniter', 'WordPress WooCommerce', 'JetBrains TeamCity')"),
			"cve_or_issue": strParam("Optional CVE ID or vulnerability summary (e.g. 'CVE-2024-4577' or 'Exposed Debug/Config')"),
			"search_query": strParam("Optional custom search query to locate public sites powered by this technology"),
			"max_sites":    map[string]any{"type": "integer", "description": "Maximum candidate sites to enroll (default 8, max 12)"},
		}, "technology"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.patchMon == nil {
				return actool.Errorf("patch monitor is not initialized"), nil
			}
			var a struct {
				Technology  string `json:"technology"`
				CVEOrIssue  string `json:"cve_or_issue"`
				SearchQuery string `json:"search_query"`
				MaxSites    int    `json:"max_sites"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			tech := strings.TrimSpace(a.Technology)
			if tech == "" {
				return actool.Errorf("technology is required"), nil
			}
			if a.MaxSites <= 0 || a.MaxSites > 12 {
				a.MaxSites = 8
			}

			// 1. Always match authorized in-scope assets first
			inScopeMatched, _ := s.patchMon.AutoMatchAuthorizedTargets(nil)

			// 2. Passive multi-engine search for publicly indexed sites running this technology
			q := strings.TrimSpace(a.SearchQuery)
			if q == "" {
				q = fmt.Sprintf(`"%s" ("powered by" OR login OR portal OR api) -site:github.com -site:stackoverflow.com`, tech)
			}
			var urls []string
			var unconfiguredEngines []string
			if s.searchOrchestrator != nil {
				if sr, serr := s.searchOrchestrator.Search(ctx, search.Request{
					Query:      q,
					Mode:       search.ModeOSINT,
					MaxResults: a.MaxSites * 2,
				}); serr == nil && sr != nil {
					for _, r := range sr.Results {
						if strings.TrimSpace(r.URL) != "" {
							urls = append(urls, r.URL)
						}
					}
				}
				unconfiguredEngines = s.unconfiguredSearchEngines()
			}

			candidates, err := s.patchMon.EnrollNotificationCandidates(tech, a.CVEOrIssue, urls)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			resp := map[string]any{
				"technology":                    tech,
				"cve_or_issue":                  a.CVEOrIssue,
				"search_query_used":             q,
				"in_scope_matched_count":        len(inScopeMatched),
				"notification_candidates_count": len(candidates),
				"notification_candidates":       candidates,
				"responsible_disclosure_policy": "Notification candidates are enrolled passively (status='notify_candidate') with security.txt contacts for responsible disclosure notification only — do NOT launch active exploit payloads against out-of-scope hosts.",
			}
			if len(unconfiguredEngines) > 0 {
				resp["api_key_suggestion"] = fmt.Sprintf("Tip: Configure %s in System -> Settings -> Network and tools to unlock deeper technology dorking and wider notification discovery.", strings.Join(unconfiguredEngines, ", "))
			}
			return jsonResult(resp)
		})
}

func (s *Server) unconfiguredSearchEngines() []string {
	if s.searchOrchestrator == nil {
		return nil
	}
	stats := s.searchOrchestrator.GetStats()
	em, _ := stats["engine_status"].(map[string]bool)
	var missing []string
	if !em["tavily"] {
		missing = append(missing, "Tavily AI (SEARCH_TAVILY_API_KEY)")
	}
	if !em["firecrawl"] {
		missing = append(missing, "Firecrawl (SEARCH_FIRECRAWL_API_KEY)")
	}
	if !em["brave"] {
		missing = append(missing, "Brave Search (SEARCH_BRAVE_API_KEY)")
	}
	return missing
}

func (s *Server) toolMatchVulnTargets() actool.CoreTool {
	return wrTool("match_vuln_targets",
		"Correlate tracked CVEs and generated exploits against BEHEMOTH's registered authorized Assets & Scope inventory by technology/product fingerprint, auto-enroll matching in-scope websites/services into Patch Monitor Targets, and return the full target list.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			if s.patchMon == nil {
				return actool.Errorf("patch monitor is not initialized"), nil
			}
			matched, err := s.patchMon.AutoMatchAuthorizedTargets(nil)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			targets, _ := s.patchMon.GetTargets()
			return jsonResult(map[string]any{
				"matched_count": len(matched),
				"matched":       matched,
				"all_targets":   targets,
			})
		})
}

func (s *Server) toolUpdateExploitTargetStatus() actool.CoreTool {
	return wrTool("update_exploit_target_status",
		"Update a Patch Monitor target's verification status (e.g. verified_vulnerable, not_affected, patched, online, offline), fingerprinted service/version, and technical notes after testing.",
		objSchema(map[string]any{
			"target_id": map[string]any{"type": "integer", "description": "Target ID from match_vuln_targets"},
			"status":    strParam("Status: verified_vulnerable | not_affected | patched | matched | online | offline"),
			"service":   strParam("Detected technology/service name (e.g. nginx, Apache, PHP/CodeIgniter)"),
			"version":   strParam("Detected software version"),
			"notes":     strParam("Verification summary and CVE test result"),
		}, "target_id", "status"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s.patchMon == nil {
				return actool.Errorf("patch monitor is not initialized"), nil
			}
			var a struct {
				TargetID int64  `json:"target_id"`
				Status   string `json:"status"`
				Service  string `json:"service"`
				Version  string `json:"version"`
				Notes    string `json:"notes"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.TargetID <= 0 || strings.TrimSpace(a.Status) == "" {
				return actool.Errorf("target_id and status are required"), nil
			}
			if err := s.patchMon.UpdateTargetVerification(a.TargetID, a.Status, a.Service, a.Version, a.Notes); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"ok": true, "target_id": a.TargetID, "status": a.Status})
		})
}

func (s *Server) toolGeneratePayload() actool.CoreTool {
	return wrTool("generate_payload",
		"Automatically generate a stealth client-side offensive JavaScript payload (cc_skimmer, cookie_exfil, crypto_swap_dom, crypto_swap_clipboard, or screen_exfil) and persist it in Patch Monitor.",
		objSchema(map[string]any{
			"type":         strParam("Payload type: cc_skimmer | cookie_exfil | crypto_swap_dom | crypto_swap_clipboard | screen_exfil"),
			"exfil_url":    strParam("Exfiltration collector endpoint URL (e.g. https://collector.behemoth.local/exfil)"),
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
		"Execute a multi-engine intelligence search across Tavily AI, Firecrawl, Brave Search, self-hosted local SearXNG, DuckDuckGo, and Sploitus Exploit DB with automatic fallback chains.",
		objSchema(map[string]any{
			"query":       strParam("Search query (e.g. 'CVE-2024-3094 PoC', 'site:target.com ext:env')"),
			"mode":        strParam("Search mode: general | exploit | technical | osint | news (default: general)"),
			"engine":      strParam("Optional specific engine override: tavily | firecrawl | brave | searxng | duckduckgo | sploitus"),
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
			missing := s.unconfiguredSearchEngines()
			if len(missing) > 0 {
				return jsonResult(map[string]any{
					"search_result":          res,
					"unconfigured_engines":   missing,
					"api_key_recommendation": fmt.Sprintf("Currently using free engines (%s). For deeper OSINT, Google dorking, and higher-recall security intelligence, suggest to the user that they can optionally add API keys for %s in System -> Settings -> Network and tools.", strings.Join(res.EnginesUsed, ", "), strings.Join(missing, ", ")),
				})
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
