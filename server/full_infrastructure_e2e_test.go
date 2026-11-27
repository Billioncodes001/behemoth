package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/behemoth/db"
	"github.com/Autumn-27/behemoth/report"
	"github.com/Autumn-27/behemoth/server/patchmonitor"
)

// TestFullInfrastructureEndToEndViaTaskEntrypoint exercises BEHEMOTH's complete
// production runtime end-to-end starting from a Multi-Agent Task launch (via Bug
// Bounty Hunt + linked Chat Conversation) and verifying live communication with:
//   1. LLMs & Task Failover Chain (Primary quota-exhausted -> automatic Backup failover + Worker Pools)
//   2. Goal Decomposer (`goals`) -> Planner (`planner`) -> Parallel Multi-Worker Pool (`work#1`, `work#2`)
//   3. Skills (`Skill` meta-tool + shorthand alias resolution + 0 missing skill calls)
//   4. MCP Servers (built-in catalog + live stdio JSON-RPC tool invocation from Worker)
//   5. External APIs (2Captcha v2 Turnstile token solving `/createTask` + `/getTaskResult`)
//   6. Multi-Engine Search (`multi_engine_search` via self-hosted SearXNG engine)
//   7. Proxies & Traffic Capture (Proxy Pool -> MITM capture proxy -> real upstream proxy transit + out-of-scope / bounty-platform block rules)
//   8. Assets, Asset Coverage & Task Intelligence (`insert_assets` + `record_intelligence`)
//   9. Patch Monitor Arsenal (`search_patch_arsenal` pre-seeded CVE lookup + `save_verified_exploit_to_patch_monitor` write-back)
//  10. Bug Bounties (scope isolation + automatic `hunting` -> `bug_found` promotion on `report_finding`)
//  11. Reporter Trigger (`Scheduler.fireToolCalls` on `report_finding` -> `update_finding_report`) & End-to-End Report (`report.Markdown`)
//  12. Cooldown / Cron Schedules (`schedule_cooldown_resume` -> `fireCooldownResumes` reviving a completed `"done"` Task for Wave 2 -> `cancel_cooldown_schedule` -> final `"done"`)
//  13. Two-Way Task -> `/chat` Real-Time SSE Callback Bridge
func TestFullInfrastructureEndToEndViaTaskEntrypoint(t *testing.T) {
	defer withZeroRetryBackoff()()

	// -------------------------------------------------------------------------
	// 1. Spin up real Vulnerable Target Web App, Upstream HTTP Proxy, 2Captcha v2
	//    API, and Local SearXNG Meta-Search API.
	// -------------------------------------------------------------------------
	var targetHits atomic.Int64
	var targetExploitConfirmed atomic.Bool
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		switch r.URL.Path {
		case "/version.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"product":"TargetPortal","framework":"CodeIgniter","version":"3.1.11","turnstile_sitekey":"0x4AAAAAA_E2E_SITEKEY"}`))
		case "/api/v1/export":
			tok := r.URL.Query().Get("cf_token")
			idParam := r.URL.Query().Get("id")
			if tok != "2CAP_TURNSTILE_SOLVED_TOKEN_E2E" {
				http.Error(w, `{"error":"turnstile_challenge_required"}`, http.StatusForbidden)
				return
			}
			if strings.Contains(idParam, "'") || strings.Contains(strings.ToUpper(idParam), "UNION") {
				targetExploitConfirmed.Store(true)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"db_error":"XPATH syntax error","leaked_banner":"BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rows":[{"id":1,"status":"ok"}]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><title>TargetPortal E2E</title></html>"))
		}
	}))
	defer targetSrv.Close()
	targetParsed, err := url.Parse(strings.Replace(targetSrv.URL, "127.0.0.1", "localhost", 1))
	if err != nil {
		t.Fatal(err)
	}
	targetBaseURL := targetParsed.String()

	var upstreamProxyRequests atomic.Int64
	upstreamProxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamProxyRequests.Add(1)
		if r.Method == http.MethodConnect {
			destConn, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				destConn.Close()
				http.Error(w, "hijack unsupported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hj.Hijack()
			if err != nil {
				destConn.Close()
				return
			}
			_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			go func() { defer destConn.Close(); defer clientConn.Close(); _, _ = io.Copy(destConn, clientConn) }()
			go func() { defer destConn.Close(); defer clientConn.Close(); _, _ = io.Copy(clientConn, destConn) }()
			return
		}
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.RequestURI, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		outReq.Header = r.Header.Clone()
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer upstreamProxySrv.Close()

	var captchaCreateHits, captchaResultHits atomic.Int64
	captchaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/createTask":
			captchaCreateHits.Add(1)
			_, _ = w.Write([]byte(`{"errorId":0,"taskId":987654}`))
		case "/getTaskResult":
			captchaResultHits.Add(1)
			_, _ = w.Write([]byte(`{"errorId":0,"status":"ready","solution":{"token":"2CAP_TURNSTILE_SOLVED_TOKEN_E2E"}}`))
		case "/getBalance":
			_, _ = w.Write([]byte(`{"errorId":0,"balance":42.50}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer captchaSrv.Close()

	var searxngQueries atomic.Int64
	searxngSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		searxngQueries.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"number_of_results":1,"results":[{"title":"CodeIgniter 3.1.11 /api/v1/export SQLi Advisory","url":"%s/api/v1/export","content":"CodeIgniter 3.1.11 export endpoint vulnerable to error-based SQL injection on id parameter.","engine":"brave","score":0.98}]}`, targetBaseURL)
	}))
	defer searxngSrv.Close()

	// -------------------------------------------------------------------------
	// 2. Spin up Primary (Quota-Exhausted) + Backup (Scripted Multi-Role OpenAI)
	//    LLM HTTP servers to exercise real OpenAI client + failover + full Engine.
	// -------------------------------------------------------------------------
	var primaryQuotaCalls atomic.Int64
	llmPrimaryExhaustedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryQuotaCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":{"type":"insufficient_quota","code":"insufficient_quota","message":"You exceeded your current quota, please check your plan and billing details."}}`))
	}))
	defer llmPrimaryExhaustedSrv.Close()

	var (
		llmMu             sync.Mutex
		goalsCalls        int
		plannerCalls      int
		workerACalls      int
		workerBCalls      int
		workerWave2Calls  int
		reporterCalls     int
		reFactIDs         = regexp.MustCompile(`"id":\s*(\d+)`)
		reIntentIDInSys   = regexp.MustCompile(`intent id:\s*(\d+)`)
		reReportFindingID = regexp.MustCompile(`finding recorded:\s*(\d+)`)
		reCooldownJobID   = regexp.MustCompile(`"id"\s*:\s*"(cd-\d+)"`)
	)

	type openAIChatReq struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role       string          `json:"role"`
			Content    json.RawMessage `json:"content"`
			ToolCallID string          `json:"tool_call_id"`
			ToolCalls  []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
		Tools []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}

	flattenMsgContent := func(raw json.RawMessage) string {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		var parts []struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(raw, &parts) == nil {
			var b strings.Builder
			for _, p := range parts {
				b.WriteString(p.Text)
				b.WriteByte('\n')
			}
			return b.String()
		}
		return string(raw)
	}

	writeOpenAIToolCalls := func(w http.ResponseWriter, stream bool, model string, calls ...map[string]any) {
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
			for i, c := range calls {
				argsBytes, _ := json.Marshal(c["args"])
				chunk := map[string]any{
					"id":      fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()),
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   model,
					"choices": []map[string]any{{
						"index": 0,
						"delta": map[string]any{
							"role": "assistant",
							"tool_calls": []map[string]any{{
								"index": i,
								"id":    fmt.Sprintf("call_%d_%d", time.Now().UnixNano(), i),
								"type":  "function",
								"function": map[string]any{
									"name":      c["name"],
									"arguments": string(argsBytes),
								},
							}},
						},
					}},
				}
				cb, _ := json.Marshal(chunk)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", cb)
			}
			fin := map[string]any{
				"id":      fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()),
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"model":   model,
				"choices": []map[string]any{{
					"index":         0,
					"delta":         map[string]any{},
					"finish_reason": "tool_calls",
				}},
				"usage": map[string]any{"prompt_tokens": 300, "completion_tokens": 80, "total_tokens": 380},
			}
			fb, _ := json.Marshal(fin)
			_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", fb)
			return
		}
		tcList := make([]map[string]any, 0, len(calls))
		for i, c := range calls {
			argsBytes, _ := json.Marshal(c["args"])
			tcList = append(tcList, map[string]any{
				"id":   fmt.Sprintf("call_%d_%d", time.Now().UnixNano(), i),
				"type": "function",
				"function": map[string]any{
					"name":      c["name"],
					"arguments": string(argsBytes),
				},
			})
		}
		resp := map[string]any{
			"id":      fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   model,
			"choices": []map[string]any{{
				"index":         0,
				"finish_reason": "tool_calls",
				"message": map[string]any{
					"role":       "assistant",
					"content":    nil,
					"tool_calls": tcList,
				},
			}},
			"usage": map[string]any{"prompt_tokens": 300, "completion_tokens": 80, "total_tokens": 380},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}

	writeOpenAIText := func(w http.ResponseWriter, stream bool, model, text string) {
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
			c1, _ := json.Marshal(map[string]any{
				"id":      fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()),
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"model":   model,
				"choices": []map[string]any{{
					"index": 0,
					"delta": map[string]any{"role": "assistant", "content": text},
				}},
			})
			c2, _ := json.Marshal(map[string]any{
				"id":      fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()),
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"model":   model,
				"choices": []map[string]any{{
					"index":         0,
					"delta":         map[string]any{},
					"finish_reason": "stop",
				}},
				"usage": map[string]any{"prompt_tokens": 250, "completion_tokens": 60, "total_tokens": 310},
			})
			_, _ = fmt.Fprintf(w, "data: %s\n\ndata: %s\n\ndata: [DONE]\n\n", c1, c2)
			return
		}
		resp := map[string]any{
			"id":      fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   model,
			"choices": []map[string]any{{
				"index":         0,
				"finish_reason": "stop",
				"message": map[string]any{
					"role":    "assistant",
					"content": text,
				},
			}},
			"usage": map[string]any{"prompt_tokens": 250, "completion_tokens": 60, "total_tokens": 310},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}

	llmActiveClusterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req openAIChatReq
		_ = json.Unmarshal(body, &req)

		var allText, sysText strings.Builder
		toolSet := map[string]bool{}
		for _, tl := range req.Tools {
			toolSet[tl.Function.Name] = true
		}
		var executedTools []string
		for _, m := range req.Messages {
			txt := flattenMsgContent(m.Content)
			allText.WriteString(txt)
			allText.WriteByte('\n')
			if m.Role == "system" {
				sysText.WriteString(txt)
				sysText.WriteByte('\n')
			}
			for _, tc := range m.ToolCalls {
				executedTools = append(executedTools, tc.Function.Name)
			}
		}
		promptBlob := allText.String()
		systemBlob := sysText.String()

		llmMu.Lock()
		defer llmMu.Unlock()

		// Role A: Goal Decomposer (`set_goals` present, `add_intent` absent)
		if toolSet["set_goals"] && !toolSet["add_intent"] {
			goalsCalls++
			if len(executedTools) == 0 {
				writeOpenAIToolCalls(w, req.Stream, req.Model, map[string]any{
					"name": "set_goals",
					"args": map[string]any{
						"goals": []map[string]any{
							{"vulnclass": "Recon", "text": "Map TargetPortal surface via Multi-Engine Search, Skills, and MCP advisory lookup"},
							{"vulnclass": "SQLi", "text": "Bypass Turnstile CAPTCHA via 2Captcha, exploit /api/v1/export SQLi via Proxy Pool, and sync PoC to Patch Monitor"},
						},
					},
				})
				return
			}
			writeOpenAIText(w, req.Stream, req.Model, "Decomposed engagement into 2 parallel sub-goals.")
			return
		}

		// Role B: Reporter (`update_finding_report` present and prompt mentions report_finding trigger)
		if strings.Contains(promptBlob, "Principal Vulnerability Report Writer") || strings.Contains(promptBlob, "was just registered via report_finding") {
			reporterCalls++
			if len(executedTools) == 0 {
				nodeID := int64(1)
				if m := reReportFindingID.FindStringSubmatch(promptBlob); len(m) >= 2 {
					nodeID, _ = strconv.ParseInt(m[1], 10, 64)
				}
				writeOpenAIToolCalls(w, req.Stream, req.Model, map[string]any{
					"name": "update_finding_report",
					"args": map[string]any{
						"finding_id": nodeID,
						"report":     "# Critical Error-Based SQL Injection in `/api/v1/export`\n\n## Overview\nVerified root DB extraction through Turnstile-protected export endpoint.\n\n## Evidence / PoC\n`BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB`\n\n## Remediation\nUse parameterized prepared statements.",
					},
				})
				return
			}
			writeOpenAIText(w, req.Stream, req.Model, "Detailed vulnerability report persisted.")
			return
		}

		// Role C: Planner (`add_intent` + `prove_goal` present)
		if toolSet["add_intent"] && toolSet["prove_goal"] {
			plannerCalls++
			// Parse pre-fetched graph_overview JSON block from promptBlob to read exact open goal IDs & fact/finding IDs!
			var openGoalIDs []int64
			var latestEvidenceID int64
			const overviewMarker = "[Current Situational Overview (pre-fetched graph_overview, identical to calling the tool; call node_detail/list_facts etc. on demand for deeper details)]:\n"
			if idx := strings.LastIndex(promptBlob, overviewMarker); idx >= 0 {
				rest := strings.TrimSpace(promptBlob[idx+len(overviewMarker):])
				if nl := strings.IndexByte(rest, '\n'); nl > 0 {
					rest = rest[:nl]
				}
				var ov struct {
					Goals []struct {
						ID    int64  `json:"id"`
						State string `json:"state"`
						Text  string `json:"text"`
					} `json:"goals"`
					RecentFacts []struct {
						ID int64 `json:"id"`
					} `json:"recent_facts"`
				}
				if json.Unmarshal([]byte(rest), &ov) == nil {
					for _, g := range ov.Goals {
						if g.State == "open" && g.ID > 0 {
							openGoalIDs = append(openGoalIDs, g.ID)
						}
					}
					if len(ov.RecentFacts) > 0 {
						latestEvidenceID = ov.RecentFacts[0].ID
					}
				}
			}

			// Wave 2 Cooldown Continuation goal open?
			if strings.Contains(promptBlob, "Scheduled Cooldown Continuation") && !strings.Contains(promptBlob, "Wave 2 cooldown verification completed") && len(executedTools) == 0 {
				writeOpenAIToolCalls(w, req.Stream, req.Model, map[string]any{
					"name": "add_intent",
					"args": map[string]any{
						"intents": []map[string]any{
							{"summary": fmt.Sprintf("[WAVE2_COOLDOWN] Execute post-cooldown verification batch against %s and cancel completed schedule", targetBaseURL), "priority": 9},
						},
					},
				})
				return
			}

			// If critical finding (Wave 1) or Wave-2 completion fact is already recorded, prove all open goals!
			wave1Ready := !strings.Contains(promptBlob, "Scheduled Cooldown Continuation") &&
				(strings.Contains(promptBlob, "BEHEMOTH_E2E_SQLI_CONFIRMED") || strings.Contains(promptBlob, "Critical SQLi in /api/v1/export"))
			wave2Ready := strings.Contains(promptBlob, "Wave 2 cooldown verification completed")
			if (wave1Ready || wave2Ready) && len(openGoalIDs) > 0 && len(executedTools) == 0 {
				evID := latestEvidenceID
				if evID <= 0 {
					if fm := reFactIDs.FindAllStringSubmatch(promptBlob, -1); len(fm) > 0 {
						evID, _ = strconv.ParseInt(fm[len(fm)-1][1], 10, 64)
					}
				}
				calls := make([]map[string]any, 0, len(openGoalIDs))
				for _, gid := range openGoalIDs {
					calls = append(calls, map[string]any{
						"name": "prove_goal",
						"args": map[string]any{
							"goal_id":     gid,
							"evidence_id": evID,
							"reason":      "Verified live SQLi exploitation, assets, intelligence, and Patch Monitor sync.",
						},
					})
				}
				writeOpenAIToolCalls(w, req.Stream, req.Model, calls...)
				return
			}

			// Initial Round 1: fan out 2 parallel Worker intents simultaneously!
			if len(executedTools) == 0 && !strings.Contains(promptBlob, "[TRACK_A_RECON]") {
				writeOpenAIToolCalls(w, req.Stream, req.Model, map[string]any{
					"name": "add_intent",
					"args": map[string]any{
						"intents": []map[string]any{
							{
								"summary":  fmt.Sprintf("[TRACK_A_RECON] Load offensive Skills, query e2e_intel_mcp + multi_engine_search, fingerprint %s/version.json, and register discovered assets", targetBaseURL),
								"priority": 9,
							},
							{
								"summary":  fmt.Sprintf("[TRACK_B_EXPLOIT] Check Proxy Pool & Patch Monitor Arsenal, solve Turnstile via 2Captcha, exploit %s/api/v1/export SQLi over proxy, save PoC to Patch Monitor, record intelligence & finding, and schedule cooldown wave", targetBaseURL),
								"priority": 10,
							},
						},
					},
				})
				return
			}

			writeOpenAIText(w, req.Stream, req.Model, "Planning round complete.")
			return
		}

		// Role D: Parallel Workers (`record_fact` present) — inspect systemBlob for this Worker's own claimed intent!
		intentID := int64(0)
		if im := reIntentIDInSys.FindStringSubmatch(systemBlob); len(im) >= 2 {
			intentID, _ = strconv.ParseInt(im[1], 10, 64)
		}

		// Worker Wave 2 (Cooldown Continuation Wave)
		if strings.Contains(systemBlob, "[WAVE2_COOLDOWN]") {
			workerWave2Calls++
			switch len(executedTools) {
			case 0:
				writeOpenAIToolCalls(w, req.Stream, req.Model, map[string]any{
					"name": "list_cooldown_schedules",
					"args": map[string]any{},
				})
				return
			case 1:
				var calls []map[string]any
				if jm := reCooldownJobID.FindStringSubmatch(promptBlob); len(jm) >= 2 {
					calls = append(calls, map[string]any{
						"name": "cancel_cooldown_schedule",
						"args": map[string]any{"job_id": jm[1]},
					})
				}
				calls = append(calls, map[string]any{
					"name": "record_fact",
					"args": map[string]any{
						"intent_id":  intentID,
						"summary":    "Wave 2 cooldown verification completed cleanly and schedule cleared",
						"detail":     "Post-cooldown auth rate-paced check confirmed finding remains reproducible; cancelled remaining cron waves.",
						"evidence":   "list_cooldown_schedules -> cancel_cooldown_schedule ok",
						"confidence": "observed",
					},
				})
				writeOpenAIToolCalls(w, req.Stream, req.Model, calls...)
				return
			default:
				writeOpenAIText(w, req.Stream, req.Model, "Wave 2 cooldown verification completed.")
				return
			}
		}

		// Worker Track A: Skills + MCP + Multi-Engine Search + Asset Registration
		if strings.Contains(systemBlob, "[TRACK_A_RECON]") {
			workerACalls++
			if len(executedTools) == 0 {
				step1 := []map[string]any{
					{
						"name": "Skill",
						"args": map[string]any{"name": "waf-bypass"}, // tests shorthand alias -> waf-and-filter-bypass!
					},
					{
						"name": "mcp__e2e_intel_mcp__lookup_internal_advisory",
						"args": map[string]any{"product": "CodeIgniter"},
					},
					{
						"name": "multi_engine_search",
						"args": map[string]any{"query": "CodeIgniter 3.1.11 export SQLi", "engine": "searxng"},
					},
					{
						"name": "insert_assets",
						"args": map[string]any{
							"assets": []map[string]any{
								{"type": "service", "url": targetBaseURL, "technologies": []string{"CodeIgniter 3.1.11"}},
								{"type": "endpoint", "url": targetBaseURL + "/api/v1/export", "method": "GET"},
							},
						},
					},
					{
						"name": "record_fact",
						"args": map[string]any{
							"intent_id":  intentID,
							"summary":    "Mapped TargetPortal CodeIgniter 3.1.11 surface, SearXNG advisory, and MCP intel",
							"detail":     "Identified /api/v1/export endpoint and Turnstile challenge sitekey.",
							"evidence":   "SearXNG + MCP lookup_internal_advisory confirmed CVE-2026-99999 in /api/v1/export",
							"confidence": "observed",
						},
					},
				}
				writeOpenAIToolCalls(w, req.Stream, req.Model, step1...)
				return
			}
			writeOpenAIText(w, req.Stream, req.Model, "Track A reconnaissance, Skill loading, MCP lookup, Multi-Engine Search, and Asset registration complete.")
			return
		}

		// Worker Track B: Proxy Status + Patch Arsenal + 2Captcha + Live Proxied Bash Exploit + Patch Writeback + Intelligence + Finding + Cooldown Schedule
		workerBCalls++
		switch {
		case len(executedTools) == 0:
			writeOpenAIToolCalls(w, req.Stream, req.Model,
				map[string]any{
					"name": "check_proxy_status",
					"args": map[string]any{},
				},
				map[string]any{
					"name": "search_patch_arsenal",
					"args": map[string]any{"query": "CodeIgniter"},
				},
				map[string]any{
					"name": "solve_captcha",
					"args": map[string]any{
						"mode":         "token",
						"captcha_type": "turnstile",
						"page_url":     targetBaseURL + "/api/v1/export",
						"site_key":     "0x4AAAAAA_E2E_SITEKEY",
					},
				},
			)
			return
		case !strings.Contains(strings.Join(executedTools, ","), "Bash"):
			// Run live curl through the Worker's active HTTP_PROXY environment (hitting MITM capture -> Upstream Proxy -> TargetSrv)!
			// `--noproxy ""` ensures curl sends even our local test-target URL through $HTTP_PROXY so MITM capture + Upstream Proxy both record it!
			curlCmd := fmt.Sprintf("curl --noproxy \"\" -sS %q", targetBaseURL+"/api/v1/export?cf_token=2CAP_TURNSTILE_SOLVED_TOKEN_E2E&id=1%27")
			writeOpenAIToolCalls(w, req.Stream, req.Model, map[string]any{
				"name": "Bash",
				"args": map[string]any{"command": curlCmd},
			})
			return
		case !strings.Contains(strings.Join(executedTools, ","), "report_finding"):
			writeOpenAIToolCalls(w, req.Stream, req.Model,
				map[string]any{
					"name": "save_verified_exploit_to_patch_monitor",
					"args": map[string]any{
						"title":             "TargetPortal CodeIgniter 3.1.11 /api/v1/export Error-Based SQLi PoC",
						"code":              fmt.Sprintf("curl -sS '%s/api/v1/export?cf_token=<token>&id=1%%27'", targetBaseURL),
						"language":          "bash",
						"exploit_type":      "sqli",
						"cve_id":            "CVE-2026-99999",
						"severity":          "critical",
						"cvss_score":        9.8,
						"affected_software": "CodeIgniter",
						"affected_versions": "<= 3.1.11",
						"verified_target":   targetBaseURL + "/api/v1/export",
						"verified_output":   "BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB",
					},
				},
				map[string]any{
					"name": "record_intelligence",
					"args": map[string]any{
						"kind":       "credential",
						"title":      "TargetPortal Export API Turnstile Session Clearance",
						"content":    `{"cf_token":"2CAP_TURNSTILE_SOLVED_TOKEN_E2E","db_role":"root"}`,
						"evidence":   "2Captcha Turnstile solve + SQLi banner BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB",
						"confidence": "observed",
						"status":     "verified",
					},
				},
				map[string]any{
					"name": "report_finding",
					"args": map[string]any{
						"intent_id": intentID,
						"vulnclass": "SQL Injection",
						"name":      "Critical SQLi in /api/v1/export",
						"severity":  "critical",
						"summary":   "Unauthenticated error-based SQL injection in `/api/v1/export?id=` after Turnstile solve yields root DB banner `BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB`.",
						"evidence":  "GET /api/v1/export?cf_token=2CAP_TURNSTILE_SOLVED_TOKEN_E2E&id=1' -> BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB",
					},
				},
				map[string]any{
					"name": "schedule_cooldown_resume",
					"args": map[string]any{
						"cooldown_minutes":        15,
						"repeat_interval_minutes": 30,
						"max_runs":                2,
						"domain":                  targetParsed.Hostname(),
						"reason":                  "Commercial proxy auth-page pacing cooldown before secondary admin batch",
						"resume_prompt":           "Verify secondary export parameters after cooldown window",
					},
				},
				map[string]any{
					"name": "record_fact",
					"args": map[string]any{
						"intent_id":  intentID,
						"summary":    "Confirmed Critical SQLi BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB, saved PoC to Patch Monitor, and scheduled cooldown wave",
						"detail":     "Solved Turnstile via 2Captcha, routed exploit through Proxy Pool, persisted finding + Patch Monitor PoC + intelligence + cooldown job.",
						"evidence":   "HTTP 200 {\"leaked_banner\":\"BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB\"}",
						"confidence": "observed",
					},
				},
			)
			return
		default:
			writeOpenAIText(w, req.Stream, req.Model, "Track B exploitation, Patch Monitor writeback, Intelligence, Finding registration, and Cooldown scheduling complete.")
			return
		}
	}))
	defer llmActiveClusterSrv.Close()

	// -------------------------------------------------------------------------
	// 3. Boot full live BEHEMOTH Manager + Traffic Capture + Server + Skills + MCP!
	// -------------------------------------------------------------------------
	// Pick an available port for the live MITM Traffic Capture proxy listener!
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	captureProxyAddr := probeLn.Addr().String()
	_ = probeLn.Close()

	dataDir := t.TempDir()
	m, err := NewManager(dataDir, captureProxyAddr)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	_ = m.SetTrafficEnabled(true)
	if err := m.SetGlobalProxy(upstreamProxySrv.URL); err != nil {
		m.Close()
		t.Fatalf("SetGlobalProxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	srcSkillsDir, err := filepath.Abs("../skills")
	if err != nil {
		cancel()
		m.Close()
		t.Fatal(err)
	}
	testSkillsDir := filepath.Join(dataDir, "skills")
	if entries, rerr := os.ReadDir(srcSkillsDir); rerr == nil {
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			skFile := filepath.Join(srcSkillsDir, ent.Name(), "SKILL.md")
			if raw, ferr := os.ReadFile(skFile); ferr == nil {
				dstDir := filepath.Join(testSkillsDir, ent.Name())
				_ = os.MkdirAll(dstDir, 0o755)
				_ = os.WriteFile(filepath.Join(dstDir, "SKILL.md"), raw, 0o644)
			}
		}
	}
	_ = m.pg.SetSetting("auto_seeded_skill_dirs_v2", "")
	s := New(ctx, m, testSkillsDir, dataDir, t.TempDir())
	t.Cleanup(func() {
		cancel()
		s.engine.Shutdown()
		m.Close()
	})

	// Configure 2Captcha external API + Local SearXNG Multi-Engine Search
	_ = m.pg.SetSetting("two_captcha_api_key", "2cap-e2e-live-key")
	_ = m.pg.SetSetting("captcha_base_url", captchaSrv.URL)
	s.searchOrchestrator.UpdateEngine("searxng", searxngSrv.URL)

	// Also import our upstream HTTP proxy into Proxy Pool v2 via the agent's own import_and_test_proxies tool!
	impIn, _ := json.Marshal(map[string]any{
		"proxies":   upstreamProxySrv.URL,
		"auto_test": false,
	})
	_, _ = s.toolImportAndTestProxies().Call(ctx, impIn, nil)

	// Seed a known CVE in Patch Monitor so `search_patch_arsenal` finds pre-existing intelligence!
	pmGen := patchmonitor.NewExploitGenerator(m.pg.DB)
	if _, _, err := pmGen.SaveVerifiedExploit(patchmonitor.VerifiedExploitInput{
		Title:            "CodeIgniter <= 3.1.11 Historical Session Advisory",
		Code:             "# baseline advisory check",
		Language:         "bash",
		ExploitType:      "sqli",
		CVEID:            "CVE-2026-99998",
		Severity:         "high",
		CVSSScore:        8.1,
		Description:      "Pre-seeded Patch Monitor entry for CodeIgniter 3.1.11",
		AffectedSoftware: "CodeIgniter",
		AffectedVersions: "<= 3.1.11",
	}); err != nil {
		t.Fatalf("seed Patch Monitor arsenal: %v", err)
	}

	// Register a live stdio JSON-RPC MCP server (`e2e_intel_mcp`) and bind it to `worker`!
	pyBin, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found on PATH for live MCP stdio verification")
	}
	mcpScript := filepath.Join(dataDir, "e2e_intel_mcp.py")
	mcpCode := `import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method", "")
    if mid is None:
        continue
    if method == "initialize":
        res = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "e2e_intel_mcp", "version": "1.0.0"}}
    elif method == "tools/list":
        res = {"tools": [{"name": "lookup_internal_advisory", "description": "Lookup internal advisory", "inputSchema": {"type": "object", "properties": {"product": {"type": "string"}}}}]}
    elif method == "tools/call":
        prod = msg.get("params", {}).get("arguments", {}).get("product", "")
        res = {"content": [{"type": "text", "text": f"INTERNAL_MCP_ADVISORY_OK:{prod}:CVE-2026-99999"}], "isError": False}
    else:
        res = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}) + "\n")
    sys.stdout.flush()
`
	if err := os.WriteFile(mcpScript, []byte(mcpCode), 0o755); err != nil {
		t.Fatal(err)
	}
	mcpArgsJSON, _ := json.Marshal([]string{"-u", mcpScript})
	mcpID, err := m.pg.SaveMCP(&db.MCPServer{
		Name:      "e2e_intel_mcp",
		Transport: "stdio",
		Command:   pyBin,
		Args:      mcpArgsJSON,
		Env:       json.RawMessage(`{}`),
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("SaveMCP: %v", err)
	}
	_ = m.pg.SaveMCPTools(mcpID, []db.MCPTool{{
		Name:        "lookup_internal_advisory",
		Description: "Lookup internal vulnerability advisory over MCP",
	}})
	if workerAg, _ := m.pg.GetAgentByKey("worker"); workerAg != nil {
		_, _ = m.pg.Exec(`INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled) VALUES($1, 'mcp', $2, '', true) ON CONFLICT DO NOTHING`, workerAg.ID, mcpID)
	}

	// Verify built-in MCP catalog was also seeded on startup (`vuln_intel`, `recon_osint`, `web_sec_analyzer`, `browser`)
	allMCPs, err := m.pg.ListMCP()
	if err != nil || len(allMCPs) < 5 {
		t.Fatalf("expected >=5 MCP servers seeded (built-ins + e2e_intel_mcp), got %d (err=%v)", len(allMCPs), err)
	}

	// Configure 2 LLM Profiles: Primary (Quota-Exhausted) -> Backup (Active OpenAI Cluster) + 2 Parallel Workers!
	primaryProfID, err := m.pg.SaveProfile(&db.LLMProfile{
		Name:      "Primary-Quota-Exhausted",
		Format:    "openai",
		BaseURL:   llmPrimaryExhaustedSrv.URL,
		APIKey:    "sk-primary-exhausted",
		Model:     "gpt-primary-e2e",
		Streaming: false,
	})
	if err != nil {
		t.Fatalf("SaveProfile primary: %v", err)
	}
	backupProfID, err := m.pg.SaveProfile(&db.LLMProfile{
		Name:      "Backup-Active-Cluster",
		Format:    "openai",
		BaseURL:   llmActiveClusterSrv.URL,
		APIKey:    "sk-backup-active",
		Model:     "gpt-backup-e2e",
		IsDefault: true,
		Streaming: false,
	})
	if err != nil {
		t.Fatalf("SaveProfile backup: %v", err)
	}
	_ = m.pg.SetActiveProfile(backupProfID)
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
	if err := m.SetWorkers(2); err != nil {
		t.Fatalf("SetWorkers(2): %v", err)
	}

	// -------------------------------------------------------------------------
	// 4. Launch Engagement via Bounty Program + Link to `/chat` Conversation SSE!
	// -------------------------------------------------------------------------
	chatConv, err := m.pg.CreateConversation("auto", "TargetPortal Assessment", nil)
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	chatSSE, unsubSSE := globalConvStreamHub.subscribe(chatConv.ID)
	defer unsubSSE()

	progID, _, err := m.pg.UpsertBountyProgram(&db.BountyProgram{
		ProgramKey:    "bugcrowd:targetportal-e2e",
		Name:          "TargetPortal E2E",
		Platform:      "bugcrowd",
		ProgramURL:    "https://bugcrowd.com/engagements/targetportal-e2e",
		SubmissionURL: "https://bugcrowd.com/engagements/targetportal-e2e",
		OffersBounty:  true,
		MinBountyUSD:  500,
		MaxBountyUSD:  15000,
		Currency:      "USD",
		InScopeAssets: []db.BountyScopeAsset{
			{Target: targetBaseURL, AssetType: "api", EligibleForBounty: true},
			{Target: "TargetPortal Desktop Installer (.dmg)", AssetType: "other", EligibleForBounty: true},
		},
		OutOfScopeAssets: []db.BountyScopeAsset{
			{Target: "outofscope.targetportal.example", AssetType: "website"},
		},
		InScopeCount: 2,
	})
	if err != nil {
		t.Fatalf("UpsertBountyProgram: %v", err)
	}

	// Create Task with explicit 2-profile failover chain `[primaryProfID, backupProfID]` via Bounty Hunt!
	_, taskIDStr, err := s.startBountyHuntForProgram(ctx, progID, "Prioritize Turnstile bypass and /api/v1/export SQLi", &primaryProfID)
	if err != nil {
		t.Fatalf("startBountyHuntForProgram: %v", err)
	}
	taskID, _ := strconv.ParseInt(taskIDStr, 10, 64)
	t.Cleanup(func() {
		s.engine.StopTask(taskIDStr)
		_ = m.pg.DeleteTask(taskID)
	})

	// Attach [Primary-Exhausted, Backup-Active] failover chain and link Task <-> Chat Conversation!
	if _, err := s.m.ReplaceTaskLLMProfiles(taskIDStr, []int64{primaryProfID, backupProfID}, primaryProfID); err != nil {
		t.Fatalf("ReplaceTaskLLMProfiles: %v", err)
	}
	if err := m.pg.UpsertTaskChatLink(taskID, chatConv.ID, "auto", 0); err != nil {
		t.Fatalf("UpsertTaskChatLink: %v", err)
	}
	taskObj, ok := m.Task(taskIDStr)
	if !ok || taskObj == nil {
		t.Fatalf("expected live task #%s", taskIDStr)
	}
	taskObj.Notify()

	// -------------------------------------------------------------------------
	// 5. Wait for Wave 1 Multi-Agent Execution to Complete (`status == "done"`)!
	// -------------------------------------------------------------------------
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if s.resolvedTaskStatus(taskObj) == "done" {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if gotStatus := s.resolvedTaskStatus(taskObj); gotStatus != "done" {
		acts, _, _ := taskObj.Store.ActivityList(nil, 0, 200)
		var dump []string
		for _, a := range acts {
			dump = append(dump, fmt.Sprintf("[%s/%s/%s err=%v] %s", a.Worker, a.Kind, a.Tool, a.IsError, a.Summary))
		}
		t.Fatalf("Wave 1 Task #%s did not reach done within timeout (status=%q, primaryCalls=%d, goalsCalls=%d, plannerCalls=%d, workerA=%d, workerB=%d):\n%s",
			taskIDStr, gotStatus, primaryQuotaCalls.Load(), goalsCalls, plannerCalls, workerACalls, workerBCalls, strings.Join(dump, "\n"))
	}

	// Sweep Task->Chat & Bounty sync + fire Reporter tool_call trigger!
	s.syncTaskChatUpdates()
	sc := &Scheduler{s: s, pg: m.pg}
	if triggers, terr := m.pg.ListEnabledTriggers(); terr == nil {
		sc.fireToolCalls(triggers)
	}

	// Wait briefly for triggered Reporter conversation to write the detailed Markdown report!
	var findings []*db.DBFinding
	reportDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(reportDeadline) {
		findings, _ = m.pg.ListTaskFindingsAfter(taskID, 0)
		if len(findings) > 0 {
			if fullF, ferr := m.pg.GetFinding(findings[0].ID); ferr == nil && fullF != nil && strings.Contains(fullF.Report, "BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB") {
				findings[0] = fullF
				break
			}
		}
		time.Sleep(120 * time.Millisecond)
	}

	// -------------------------------------------------------------------------
	// 6. Assert ALL 12 Infrastructure Subsystems Operated End-to-End in Wave 1!
	// -------------------------------------------------------------------------

	// (A) LLM Failover Chain: Primary failed with 402 Quota -> automatically switched active profile to Backup!
	if primaryQuotaCalls.Load() == 0 {
		t.Fatal("expected Primary quota-exhausted profile to be tried before automatic failover")
	}
	llmSnap := taskObj.llmStateSnapshot()
	if llmSnap.ActiveID == nil || *llmSnap.ActiveID != backupProfID {
		t.Fatalf("expected Task active LLM profile to fail over to Backup #%d, got %+v", backupProfID, llmSnap)
	}

	// (B) Goal Decomposer + Planner + Parallel Workers all ran!
	if goalsCalls == 0 || plannerCalls < 2 || workerACalls == 0 || workerBCalls == 0 {
		t.Fatalf("expected Goals + Planner + both Parallel Workers to execute, got goals=%d planner=%d workerA=%d workerB=%d",
			goalsCalls, plannerCalls, workerACalls, workerBCalls)
	}

	// (C) Skills: shorthand `waf-bypass` resolved cleanly to `waf-and-filter-bypass` with ZERO missing skill calls!
	missingSkills, err := m.pg.MissingSkillStats(20)
	if err != nil {
		t.Fatalf("MissingSkillStats: %v", err)
	}
	for _, ms := range missingSkills {
		if ms.Skill == "waf-bypass" || ms.Skill == "waf-and-filter-bypass" {
			t.Fatalf("unexpected missing skill call recorded: %+v", ms)
		}
	}
	taskSkills, _ := m.pg.SkillCallsByTask(taskID)
	if len(taskSkills) == 0 {
		t.Fatalf("expected Skill usage recorded for Task #%d, got 0", taskID)
	}

	// (D) MCP stdio server + Multi-Engine Search (SearXNG) + 2Captcha v2 External API all handled live Worker calls!
	if searxngQueries.Load() == 0 {
		t.Fatal("expected Worker to query Multi-Engine Search (SearXNG)")
	}
	if captchaCreateHits.Load() == 0 || captchaResultHits.Load() == 0 {
		t.Fatalf("expected Worker solve_captcha to call 2Captcha /createTask (%d) and /getTaskResult (%d)",
			captchaCreateHits.Load(), captchaResultHits.Load())
	}
	allActs, _, _ := taskObj.Store.ActivityList(nil, 0, 500)
	sawMCPResult := false
	for _, a := range allActs {
		if a.Kind == "tool_result" && strings.Contains(a.Tool, "lookup_internal_advisory") && !a.IsError {
			det, _ := taskObj.Store.ActivityDetail(a.ID)
			if strings.Contains(det+a.Summary, "INTERNAL_MCP_ADVISORY_OK:CodeIgniter:CVE-2026-99999") {
				sawMCPResult = true
				break
			}
		}
	}
	if !sawMCPResult {
		t.Fatal("expected Worker to invoke live stdio MCP tool mcp__e2e_intel_mcp__lookup_internal_advisory and receive CVE-2026-99999")
	}

	// (E) Proxy Pool + MITM Traffic Capture + Vulnerable Target Exploit Proof!
	if !targetExploitConfirmed.Load() || targetHits.Load() == 0 {
		t.Fatalf("expected live SQLi exploit request to hit TargetPortal with solved 2Captcha token (hits=%d confirmed=%v)",
			targetHits.Load(), targetExploitConfirmed.Load())
	}
	if upstreamProxyRequests.Load() == 0 {
		t.Fatal("expected Worker HTTP probe to route through configured Proxy Pool upstream proxy!")
	}
	var capturedTrafficCount int
	_ = m.traffic.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&capturedTrafficCount)
	if capturedTrafficCount == 0 {
		t.Fatal("expected MITM Traffic Capture DB to record Worker HTTP exchange(s)")
	}

	// (F) Assets, Scope Guard Isolation (`bugcrowd.com` & `outofscope` blocked), and Task Intelligence!
	var bugcrowdAssets int
	_ = m.pg.QueryRow(`SELECT COUNT(*) FROM assets WHERE $1 = ANY(task_ids) AND LOWER(COALESCE(domain,'')) LIKE '%bugcrowd.com%'`, taskID).Scan(&bugcrowdAssets)
	if bugcrowdAssets != 0 {
		t.Fatalf("expected 0 bugcrowd.com assets linked to Task #%d, got %d", taskID, bugcrowdAssets)
	}
	var taskEndpointAssets int
	_ = m.pg.QueryRow(`SELECT COUNT(*) FROM assets WHERE $1 = ANY(task_ids) AND type IN ('service','endpoint')`, taskID).Scan(&taskEndpointAssets)
	if taskEndpointAssets < 2 {
		t.Fatalf("expected >=2 service/endpoint assets registered on Task #%d, got %d", taskID, taskEndpointAssets)
	}
	intelList, err := m.pg.ListIntelligence(ctx, db.IntelligenceFilter{TaskID: taskID, Limit: 20})
	if err != nil || intelList == nil || len(intelList.Items) == 0 {
		t.Fatalf("expected Task Intelligence credential recorded on Task #%d, got err=%v list=%+v", taskID, err, intelList)
	}

	// (G) Patch Monitor Two-Way Loop: both pre-seeded CVE-2026-99998 AND Worker-saved verified PoC CVE-2026-99999 present!
	_, exploitsAfter, err := pmGen.SearchArsenal("CVE-2026-99999", 10)
	if err != nil || len(exploitsAfter) == 0 {
		t.Fatalf("expected Worker's newly verified SQLi PoC (CVE-2026-99999) saved in Patch Monitor Arsenal, got len=%d err=%v", len(exploitsAfter), err)
	}

	// (H) Findings + Triggered Reporter Detailed Report + Automatic Bounty Tracker `hunting` -> `bug_found` Promotion!
	if len(findings) != 1 || findings[0].Severity != "critical" {
		t.Fatalf("expected 1 critical finding recorded on Task #%d, got %+v", taskID, findings)
	}
	fullFinding, _ := m.pg.GetFinding(findings[0].ID)
	if fullFinding == nil || !strings.Contains(fullFinding.Report, "BEHEMOTH_E2E_SQLI_CONFIRMED_ROOT_DB") {
		t.Fatalf("expected Reporter trigger to populate detailed Markdown report on Finding #%d, got: %+v", findings[0].ID, fullFinding)
	}
	bountyAfter, err := m.pg.GetBountyProgram(progID)
	if err != nil || bountyAfter == nil || bountyAfter.TrackerStatus != "bug_found" {
		t.Fatalf("expected Bounty Program #%d to auto-promote from hunting -> bug_found, got %+v (err=%v)", progID, bountyAfter, err)
	}

	// (I) End-to-End Task Engagement Report (`report.Markdown`) & Live `/chat` SSE Updates!
	mdReport := report.Markdown(report.Input{
		TaskID:      taskIDStr,
		Title:       "Bounty · TargetPortal E2E",
		Goal:        taskObj.Goal,
		Status:      "done",
		DBFindings:  []*db.DBFinding{fullFinding},
		CreatedAt:   time.Now().Add(-2 * time.Minute),
		GeneratedAt: time.Now(),
	})
	if !strings.Contains(mdReport, "### Engagement Scope & Briefing") || !strings.Contains(mdReport, "Critical SQLi in /api/v1/export") {
		t.Fatalf("expected End-to-End Task Report to include Engagement Scope & Briefing and Critical SQLi finding, got:\n%s", mdReport)
	}

	chatActivities, _, err := m.pg.ConvActivityList(chatConv.ID, 0, 50)
	if err != nil || len(chatActivities) < 3 {
		t.Fatalf("expected >=3 live updates pushed back to linked /chat Conversation #%d (goals + finding + completion), got %d (err=%v)",
			chatConv.ID, len(chatActivities), err)
	}
	sseFrames := 0
drainChatSSE:
	for {
		select {
		case fr := <-chatSSE:
			if fr.Event == "activity" {
				sseFrames++
			}
		case <-time.After(30 * time.Millisecond):
			break drainChatSSE
		}
	}
	if sseFrames < 3 {
		t.Fatalf("expected >=3 real-time SSE activity frames delivered to /chat, got %d", sseFrames)
	}

	// -------------------------------------------------------------------------
	// 7. Wave 2: Fast-Forward Cooldown Schedule & Verify Revival of `"done"` Task!
	// -------------------------------------------------------------------------
	cooldownJobsMu.Lock()
	jobs := s.loadCooldownResumeJobsLocked()
	if len(jobs) == 0 {
		cooldownJobsMu.Unlock()
		t.Fatal("expected Worker to persist a CooldownResumeJob via schedule_cooldown_resume")
	}
	for i := range jobs {
		if jobs[i].TaskID == taskID {
			jobs[i].NextFireUnix = time.Now().Unix() - 5
		}
	}
	_ = s.saveCooldownResumeJobsLocked(jobs)
	cooldownJobsMu.Unlock()

	sc.fireCooldownResumes()

	// Wait for revived Task to execute Wave 2 Worker (`cancel_cooldown_schedule` + `record_fact`),
	// prove the new continuation goal, and settle back to `"done"`!
	wave2Deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(wave2Deadline) {
		llmMu.Lock()
		w2 := workerWave2Calls
		llmMu.Unlock()
		if w2 > 0 && s.resolvedTaskStatus(taskObj) == "done" {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if workerWave2Calls == 0 || s.resolvedTaskStatus(taskObj) != "done" {
		t.Fatalf("expected Cooldown Schedule to revive completed Task #%s, run Wave 2 Worker (%d calls), and finish done (got status=%q)",
			taskIDStr, workerWave2Calls, s.resolvedTaskStatus(taskObj))
	}

	cooldownJobsMu.Lock()
	remainingJobs := s.loadCooldownResumeJobsLocked()
	cooldownJobsMu.Unlock()
	for _, rj := range remainingJobs {
		if rj.TaskID == taskID && rj.Enabled {
			t.Fatalf("expected Wave 2 Worker to cancel remaining cooldown schedule via cancel_cooldown_schedule, found still-enabled job: %+v", rj)
		}
	}
}
