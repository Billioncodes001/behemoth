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
	"github.com/Autumn-27/behemoth/server/patchmonitor"
)

// TestFindingsTrafficRepeaterEntrypointsFullInfrastructureE2E validates the entire
// BEHEMOTH infrastructure end-to-end starting from the real HTTP API entry points
// of the Findings page, Traffic page, and Repeater page:
//
//   Entry Point 1 — Findings Page (`/function/findings`):
//     - Continue Pentest on a Completed Task (`POST /api/chat?task=<id>`) ->
//       Task Main Agent (`set_goals` + `add_hint`) revives Completed Task ->
//       LLM Quota Failover (`Primary 402` -> `Backup`) -> Planner -> Parallel Workers ->
//       Skills (`waf-bypass` alias -> 0 missing), live stdio MCP server,
//       Multi-Engine Search (SearXNG), 2Captcha v2 Turnstile, Proxy Pool + MITM Capture,
//       Assets, Task Intelligence, Patch Monitor (lookup + PoC writeback),
//       Finding escalation + new Critical Finding, Bug Bounty auto-promotion (`bug_found`),
//       Reporter trigger (`update_finding_report`), and linked `/chat` SSE updates.
//     - Retest Finding (`POST /api/exploration/findings/{id}/retests`) ->
//       dedicated `retester` agent (`get_finding_retest_context` -> live verify ->
//       `record_finding_retest_result` -> sealed `still_vulnerable`).
//
//   Entry Point 2 — Traffic Page (`/function/traffic`):
//     - `GET /api/traffic` & `GET /api/traffic/hosts` verify live Worker capture.
//     - `GET /api/traffic/exchange?id=...` retrieves raw request/response (used for Send to Repeater).
//     - `POST /api/exploration/findings/{id}/traffic` binds captured packet as `proof`
//       and verifies `GET /api/report?task=<id>` reflects it.
//
//   Entry Point 3 — Repeater Page (`/function/repeater`):
//     - `POST /api/repeater/send` replays a modified request through Recording Proxy (MITM)
//       + Upstream Proxy Pool -> Target -> auto-captured back in `GET /api/traffic` ->
//       bound back to the Finding as `verification`.
//     - Cooldown Schedule Wave 2 (`Scheduler.fireCooldownResumes`) revives the completed Task,
//       clears the schedule via `cancel_cooldown_schedule`, and settles cleanly back to `"done"`.
func TestFindingsTrafficRepeaterEntrypointsFullInfrastructureE2E(t *testing.T) {
	defer withZeroRetryBackoff()()
	t.Setenv(repeaterAllowLocalEnv, "1")

	// -------------------------------------------------------------------------
	// 1. Live Target Web App, Upstream Proxy, 2Captcha v2 API, and SearXNG API
	// -------------------------------------------------------------------------
	var targetHits, repeaterHeaderHits atomic.Int64
	var targetExploitConfirmed atomic.Bool
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.Header.Get("X-Repeater-Verify") == "behemoth-e2e" {
			repeaterHeaderHits.Add(1)
		}
		switch r.URL.Path {
		case "/api/v1/export":
			tok := r.URL.Query().Get("cf_token")
			idParam := r.URL.Query().Get("id")
			if tok != "2CAP_E2E_ENTRYPOINTS_TOKEN" {
				http.Error(w, `{"error":"turnstile_required"}`, http.StatusForbidden)
				return
			}
			if strings.Contains(idParam, "'") || strings.Contains(strings.ToUpper(idParam), "UNION") {
				targetExploitConfirmed.Store(true)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"db_error":"XPATH syntax error","leaked_banner":"BEHEMOTH_ENTRYPOINTS_SQLI_ROOT"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rows":[{"id":1}]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><title>TargetPortal Entrypoints E2E</title></html>`))
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
			dialHost := r.Host
			if strings.HasPrefix(dialHost, "targetportal.e2e.local") {
				dialHost = targetSrv.Listener.Addr().String()
			}
			destConn, err := net.DialTimeout("tcp", dialHost, 5*time.Second)
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
		outURL := r.RequestURI
		if strings.Contains(outURL, "targetportal.e2e.local") {
			outURL = strings.Replace(outURL, "targetportal.e2e.local", targetSrv.Listener.Addr().String(), 1)
		}
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL, r.Body)
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
			_, _ = w.Write([]byte(`{"errorId":0,"taskId":554433}`))
		case "/getTaskResult":
			captchaResultHits.Add(1)
			_, _ = w.Write([]byte(`{"errorId":0,"status":"ready","solution":{"token":"2CAP_E2E_ENTRYPOINTS_TOKEN"}}`))
		case "/getBalance":
			_, _ = w.Write([]byte(`{"errorId":0,"balance":50.00}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer captchaSrv.Close()

	var searxngQueries atomic.Int64
	searxngSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		searxngQueries.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"number_of_results":1,"results":[{"title":"CodeIgniter 3.1.11 /api/v1/export SQLi","url":"%s/api/v1/export","content":"Error-based SQLi on id parameter.","engine":"brave","score":0.99}]}`, targetBaseURL)
	}))
	defer searxngSrv.Close()

	// -------------------------------------------------------------------------
	// 2. Primary (Quota-Exhausted) + Backup (Scripted Multi-Role OpenAI) LLMs
	// -------------------------------------------------------------------------
	var primaryQuotaCalls atomic.Int64
	llmPrimaryExhaustedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryQuotaCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":{"type":"insufficient_quota","code":"insufficient_quota","message":"You exceeded your current quota."}}`))
	}))
	defer llmPrimaryExhaustedSrv.Close()

	var (
		llmMu             sync.Mutex
		mainAgentCalls    int
		plannerCalls      int
		workerACalls      int
		workerBCalls      int
		workerWave2Calls  int
		retesterCalls     int
		reporterCalls     int
		reFactIDs         = regexp.MustCompile(`"id":\s*(\d+)`)
		reIntentIDInSys   = regexp.MustCompile(`intent id:\s*(\d+)`)
		reReportFindingID = regexp.MustCompile(`finding recorded:\s*(\d+)`)
		reCooldownJobID   = regexp.MustCompile(`"id"\s*:\s*"(cd-\d+)"`)
		initialFindingID  int64
	)

	type openAIChatReq struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role      string          `json:"role"`
			Content   json.RawMessage `json:"content"`
			ToolCalls []struct {
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

	flattenMsg := func(raw json.RawMessage) string {
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

	writeToolCalls := func(w http.ResponseWriter, model string, calls ...map[string]any) {
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
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
			"usage": map[string]any{"prompt_tokens": 240, "completion_tokens": 70, "total_tokens": 310},
		})
	}

	writeText := func(w http.ResponseWriter, model, text string) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
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
			"usage": map[string]any{"prompt_tokens": 200, "completion_tokens": 50, "total_tokens": 250},
		})
	}

	llmBackupClusterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			txt := flattenMsg(m.Content)
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

		// Role 1: Dedicated Finding Retester (`record_finding_retest_result` present)
		if toolSet["record_finding_retest_result"] {
			retesterCalls++
			switch len(executedTools) {
			case 0:
				writeToolCalls(w, req.Model, map[string]any{
					"name": "get_finding_retest_context",
					"args": map[string]any{},
				})
				return
			case 1:
				writeToolCalls(w, req.Model, map[string]any{
					"name": "record_finding_retest_result",
					"args": map[string]any{
						"verdict":  "reproduced",
						"summary":  "Retest confirmed /api/v1/export SQLi remains exploitable.",
						"evidence": "GET /api/v1/export?cf_token=2CAP_E2E_ENTRYPOINTS_TOKEN&id=1' -> BEHEMOTH_ENTRYPOINTS_SQLI_ROOT",
					},
				})
				return
			default:
				writeText(w, req.Model, "Finding retest completed: still_vulnerable.")
				return
			}
		}

		// Role 2: Triggered Reporter (`update_finding_report` on report_finding trigger)
		if strings.Contains(promptBlob, "Principal Vulnerability Report Writer") || strings.Contains(promptBlob, "was just registered via report_finding") {
			reporterCalls++
			if len(executedTools) == 0 {
				nodeID := int64(1)
				if m := reReportFindingID.FindStringSubmatch(promptBlob); len(m) >= 2 {
					nodeID, _ = strconv.ParseInt(m[1], 10, 64)
				}
				writeToolCalls(w, req.Model, map[string]any{
					"name": "update_finding_report",
					"args": map[string]any{
						"finding_id": nodeID,
						"report":     "# Critical Error-Based SQLi in `/api/v1/export`\n\nVerified live extraction: `BEHEMOTH_ENTRYPOINTS_SQLI_ROOT`.",
					},
				})
				return
			}
			writeText(w, req.Model, "Detailed report written.")
			return
		}

		// Role 3: Task Main Agent (triggered by Findings -> Continue Pentest via POST /api/chat?task=<id>)
		if toolSet["set_goals"] && toolSet["add_hint"] {
			mainAgentCalls++
			if len(executedTools) == 0 {
				writeToolCalls(w, req.Model,
					map[string]any{
						"name": "set_goals",
						"args": map[string]any{
							"goals": []map[string]any{
								{"vulnclass": "Recon", "text": "Continue surface recon via Skills, MCP, and SearXNG"},
								{"vulnclass": "SQLi", "text": "Bypass Turnstile via 2Captcha, exploit /api/v1/export SQLi via Proxy Pool, escalate Finding, and sync Patch Monitor"},
							},
						},
					},
					map[string]any{
						"name": "add_hint",
						"args": map[string]any{
							"text": fmt.Sprintf("Prioritize full exploitation of %s/api/v1/export and escalate existing Finding #%d", targetBaseURL, initialFindingID),
						},
					},
				)
				return
			}
			writeText(w, req.Model, "Revived Task in parallel multi-agent mode with 2 new goals and strategic hint.")
			return
		}

		// Role 4: Planner (`add_intent` + `prove_goal`)
		if toolSet["add_intent"] && toolSet["prove_goal"] {
			plannerCalls++
			var openGoalIDs []int64
			var latestEvID int64
			const marker = "[Current Situational Overview (pre-fetched graph_overview, identical to calling the tool; call node_detail/list_facts etc. on demand for deeper details)]:\n"
			if idx := strings.LastIndex(promptBlob, marker); idx >= 0 {
				rest := strings.TrimSpace(promptBlob[idx+len(marker):])
				if nl := strings.IndexByte(rest, '\n'); nl > 0 {
					rest = rest[:nl]
				}
				var ov struct {
					Goals []struct {
						ID    int64  `json:"id"`
						State string `json:"state"`
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
						latestEvID = ov.RecentFacts[0].ID
					}
				}
			}

			// Wave 2 Cooldown Continuation
			if strings.Contains(promptBlob, "Scheduled Cooldown Continuation") && !strings.Contains(promptBlob, "Wave 2 cooldown verification completed") && len(executedTools) == 0 {
				writeToolCalls(w, req.Model, map[string]any{
					"name": "add_intent",
					"args": map[string]any{
						"intents": []map[string]any{
							{"summary": fmt.Sprintf("[WAVE2_COOLDOWN] Verify post-cooldown batch on %s and cancel schedule", targetBaseURL), "priority": 9},
						},
					},
				})
				return
			}

			wave1Ready := !strings.Contains(promptBlob, "Scheduled Cooldown Continuation") &&
				(strings.Contains(promptBlob, "BEHEMOTH_ENTRYPOINTS_SQLI_ROOT") || strings.Contains(promptBlob, "Critical SQLi in /api/v1/export"))
			wave2Ready := strings.Contains(promptBlob, "Wave 2 cooldown verification completed")
			if (wave1Ready || wave2Ready) && len(openGoalIDs) > 0 && len(executedTools) == 0 {
				evID := latestEvID
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
							"reason":      "Verified exploitation and infrastructure sync.",
						},
					})
				}
				writeToolCalls(w, req.Model, calls...)
				return
			}

			if len(executedTools) == 0 && !strings.Contains(promptBlob, "[TRACK_A_RECON]") {
				writeToolCalls(w, req.Model, map[string]any{
					"name": "add_intent",
					"args": map[string]any{
						"intents": []map[string]any{
							{"summary": fmt.Sprintf("[TRACK_A_RECON] Load Skills, query MCP + SearXNG, register assets on %s", targetBaseURL), "priority": 9},
							{"summary": fmt.Sprintf("[TRACK_B_EXPLOIT] Check Proxy + Patch Arsenal, solve 2Captcha Turnstile, exploit %s/api/v1/export, escalate Finding, save PoC, record intel & schedule cooldown", targetBaseURL), "priority": 10},
						},
					},
				})
				return
			}
			writeText(w, req.Model, "Planning round finished.")
			return
		}

		// Role 5: Parallel Workers (`record_fact`)
		intentID := int64(0)
		if im := reIntentIDInSys.FindStringSubmatch(systemBlob); len(im) >= 2 {
			intentID, _ = strconv.ParseInt(im[1], 10, 64)
		}

		if strings.Contains(systemBlob, "[WAVE2_COOLDOWN]") {
			workerWave2Calls++
			switch len(executedTools) {
			case 0:
				writeToolCalls(w, req.Model, map[string]any{"name": "list_cooldown_schedules", "args": map[string]any{}})
				return
			case 1:
				var calls []map[string]any
				if jms := reCooldownJobID.FindAllStringSubmatch(promptBlob, -1); len(jms) > 0 {
					calls = append(calls, map[string]any{"name": "cancel_cooldown_schedule", "args": map[string]any{"job_id": jms[len(jms)-1][1]}})
				}
				calls = append(calls, map[string]any{
					"name": "record_fact",
					"args": map[string]any{
						"intent_id":  intentID,
						"summary":    "Wave 2 cooldown verification completed cleanly",
						"detail":     "Post-cooldown verification succeeded and cron schedule cancelled.",
						"evidence":   "cancel_cooldown_schedule ok",
						"confidence": "observed",
					},
				})
				writeToolCalls(w, req.Model, calls...)
				return
			default:
				writeText(w, req.Model, "Wave 2 done.")
				return
			}
		}

		if strings.Contains(systemBlob, "[TRACK_A_RECON]") {
			workerACalls++
			if len(executedTools) == 0 {
				writeToolCalls(w, req.Model,
					map[string]any{"name": "Skill", "args": map[string]any{"name": "waf-bypass"}},
					map[string]any{"name": "mcp__e2e_intel_mcp__lookup_internal_advisory", "args": map[string]any{"product": "CodeIgniter"}},
					map[string]any{"name": "multi_engine_search", "args": map[string]any{"query": "CodeIgniter 3.1.11 export SQLi", "engine": "searxng"}},
					map[string]any{
						"name": "insert_assets",
						"args": map[string]any{
							"assets": []map[string]any{
								{"type": "service", "url": targetBaseURL, "technologies": []string{"CodeIgniter 3.1.11"}},
								{"type": "endpoint", "url": targetBaseURL + "/api/v1/export", "method": "GET"},
							},
						},
					},
					map[string]any{
						"name": "record_fact",
						"args": map[string]any{
							"intent_id":  intentID,
							"summary":    "Track A mapped CodeIgniter 3.1.11 /api/v1/export via Skills, MCP, and SearXNG",
							"detail":     "Registered service and endpoint assets.",
							"evidence":   "INTERNAL_MCP_ADVISORY_OK:CodeIgniter:CVE-2026-88888",
							"confidence": "observed",
						},
					},
				)
				return
			}
			writeText(w, req.Model, "Track A finished.")
			return
		}

		workerBCalls++
		switch {
		case len(executedTools) == 0:
			writeToolCalls(w, req.Model,
				map[string]any{"name": "check_proxy_status", "args": map[string]any{}},
				map[string]any{"name": "search_patch_arsenal", "args": map[string]any{"query": "CodeIgniter"}},
				map[string]any{
					"name": "solve_captcha",
					"args": map[string]any{
						"mode":         "token",
						"captcha_type": "turnstile",
						"page_url":     targetBaseURL + "/api/v1/export",
						"site_key":     "0x4AAAAAA_ENTRYPOINTS",
					},
				},
			)
			return
		case !strings.Contains(strings.Join(executedTools, ","), "Bash"):
			curlCmd := fmt.Sprintf("curl --noproxy \"\" -sS %q", targetBaseURL+"/api/v1/export?cf_token=2CAP_E2E_ENTRYPOINTS_TOKEN&id=1%27")
			writeToolCalls(w, req.Model, map[string]any{"name": "Bash", "args": map[string]any{"command": curlCmd}})
			return
		case !strings.Contains(strings.Join(executedTools, ","), "report_finding"):
			writeToolCalls(w, req.Model,
				map[string]any{
					"name": "update_finding",
					"args": map[string]any{
						"finding_id":      initialFindingID,
						"severity":        "high",
						"status":          "confirmed",
						"summary":         "Escalated after live exploitation confirmation on /api/v1/export.",
						"append_evidence": "Confirmed via live proxied curl: BEHEMOTH_ENTRYPOINTS_SQLI_ROOT",
					},
				},
				map[string]any{
					"name": "save_verified_exploit_to_patch_monitor",
					"args": map[string]any{
						"title":             "TargetPortal /api/v1/export Error-Based SQLi PoC",
						"code":              fmt.Sprintf("curl -sS '%s/api/v1/export?cf_token=<token>&id=1%%27'", targetBaseURL),
						"language":          "bash",
						"exploit_type":      "sqli",
						"cve_id":            "CVE-2026-88888",
						"severity":          "critical",
						"cvss_score":        9.8,
						"affected_software": "CodeIgniter",
						"affected_versions": "<= 3.1.11",
						"verified_target":   targetBaseURL + "/api/v1/export",
						"verified_output":   "BEHEMOTH_ENTRYPOINTS_SQLI_ROOT",
					},
				},
				map[string]any{
					"name": "record_intelligence",
					"args": map[string]any{
						"kind":       "credential",
						"title":      "TargetPortal Turnstile Clearance",
						"content":    `{"cf_token":"2CAP_E2E_ENTRYPOINTS_TOKEN"}`,
						"evidence":   "2Captcha + proxied curl BEHEMOTH_ENTRYPOINTS_SQLI_ROOT",
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
						"summary":   "Confirmed unauthenticated SQLi yielding `BEHEMOTH_ENTRYPOINTS_SQLI_ROOT`.",
						"evidence":  "GET /api/v1/export?cf_token=2CAP_E2E_ENTRYPOINTS_TOKEN&id=1' -> BEHEMOTH_ENTRYPOINTS_SQLI_ROOT",
					},
				},
				map[string]any{
					"name": "schedule_cooldown_resume",
					"args": map[string]any{
						"cooldown_minutes":        15,
						"repeat_interval_minutes": 30,
						"max_runs":                2,
						"domain":                  targetParsed.Hostname(),
						"reason":                  "Auth-page cooldown before Wave 2",
						"resume_prompt":           "Run post-cooldown verification batch",
					},
				},
				map[string]any{
					"name": "record_fact",
					"args": map[string]any{
						"intent_id":  intentID,
						"summary":    "Confirmed Critical SQLi BEHEMOTH_ENTRYPOINTS_SQLI_ROOT and escalated preliminary finding",
						"detail":     "Completed Track B exploitation, Patch Monitor writeback, intelligence, finding, and cooldown job.",
						"evidence":   "BEHEMOTH_ENTRYPOINTS_SQLI_ROOT",
						"confidence": "observed",
					},
				},
			)
			return
		default:
			writeText(w, req.Model, "Track B finished.")
			return
		}
	}))
	defer llmBackupClusterSrv.Close()

	// -------------------------------------------------------------------------
	// 3. Boot Complete BEHEMOTH Server + MITM Recording Proxy + Authenticated HTTP Client
	// -------------------------------------------------------------------------
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
			if raw, ferr := os.ReadFile(filepath.Join(srcSkillsDir, ent.Name(), "SKILL.md")); ferr == nil {
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

	jwtToken, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	apiReq := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+jwtToken)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	// Configure External APIs (2Captcha v2 + SearXNG), Patch Monitor seed, live stdio MCP, and 2 LLM Profiles!
	_ = m.pg.SetSetting("captcha_api_key", "2cap-entrypoints-key")
	_ = m.pg.SetSetting("captcha_base_url", captchaSrv.URL)
	s.searchOrchestrator.UpdateEngine("searxng", searxngSrv.URL)

	pmGen := patchmonitor.NewExploitGenerator(m.pg.DB)
	if _, _, err := pmGen.SaveVerifiedExploit(patchmonitor.VerifiedExploitInput{
		Title:            "CodeIgniter 3.1.11 Historical Advisory",
		Code:             "# baseline",
		Language:         "bash",
		ExploitType:      "sqli",
		CVEID:            "CVE-2026-88887",
		Severity:         "high",
		CVSSScore:        8.0,
		AffectedSoftware: "CodeIgniter",
		AffectedVersions: "<= 3.1.11",
	}); err != nil {
		t.Fatalf("seed Patch Monitor: %v", err)
	}

	pyBin, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for live MCP stdio test")
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
        res = {"tools": [{"name": "lookup_internal_advisory", "description": "Lookup advisory", "inputSchema": {"type": "object", "properties": {"product": {"type": "string"}}}}]}
    elif method == "tools/call":
        prod = msg.get("params", {}).get("arguments", {}).get("product", "")
        res = {"content": [{"type": "text", "text": f"INTERNAL_MCP_ADVISORY_OK:{prod}:CVE-2026-88888"}], "isError": False}
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
		Name: "e2e_intel_mcp", Transport: "stdio", Command: pyBin, Args: mcpArgsJSON, Env: json.RawMessage(`{}`), Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteMCP(mcpID) })
	_ = m.pg.SaveMCPTools(mcpID, []db.MCPTool{{Name: "lookup_internal_advisory", Description: "Lookup advisory"}})
	if workerAg, _ := m.pg.GetAgentByKey("worker"); workerAg != nil {
		_, _ = m.pg.Exec(`INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled) VALUES($1, 'mcp', $2, '', true) ON CONFLICT DO NOTHING`, workerAg.ID, mcpID)
	}

	primaryProfID, err := m.pg.SaveProfile(&db.LLMProfile{
		Name: "Primary-Exhausted", Format: "openai", BaseURL: llmPrimaryExhaustedSrv.URL, APIKey: "sk-1", Model: "gpt-p1", Streaming: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	backupProfID, err := m.pg.SaveProfile(&db.LLMProfile{
		Name: "Backup-Cluster", Format: "openai", BaseURL: llmBackupClusterSrv.URL, APIKey: "sk-2", Model: "gpt-p2", IsDefault: true, Streaming: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = m.pg.SetActiveProfile(backupProfID)
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
	if err := m.SetWorkers(2); err != nil {
		t.Fatal(err)
	}

	// -------------------------------------------------------------------------
	// 4. Seed Initial State: Completed Task + Preliminary Medium Finding +
	//    Linked Bug Bounty Program + Linked `/chat` Conversation SSE!
	// -------------------------------------------------------------------------
	taskObj, err := m.CreateTaskWithOptions("Initial Pentest · TargetPortal", "Initial surface scan of "+targetBaseURL, db.TaskCreateOptions{
		Name:          "TargetPortal Pentest",
		LLMProfileIDs: []int64{primaryProfID, backupProfID},
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions: %v", err)
	}
	taskID, _ := strconv.ParseInt(taskObj.ID, 10, 64)
	t.Cleanup(func() {
		s.engine.StopTask(taskObj.ID)
		_ = m.pg.DeleteTask(taskID)
	})
	// Mark Task Completed (`done`), mirroring your Federal Polyede Pentest Task #1!
	if err := m.SetTaskStatus(taskObj.ID, "done"); err != nil {
		t.Fatalf("SetTaskStatus done: %v", err)
	}
	// Record an initial preliminary Medium finding attached to that Completed Task!
	recFinding, err := s.evidenceStore().Record(ctx, db.RecordFindingInput{
		TaskID: taskID, ExplorationID: taskObj.ExpID, Worker: "work#1",
		VulnClass: "Information Disclosure", Name: "Preliminary Export Endpoint Exposure",
		Severity: "medium", Summary: "Unauthenticated export endpoint responds to probes.", Evidence: "HTTP 403 turnstile_required",
	}, nil)
	if err != nil {
		t.Fatalf("Record initial finding: %v", err)
	}
	initialFindingID = recFinding.FindingID

	// Link a Bug Bounty Program (`hunting`) and a `/chat` Conversation (subscribed to SSE) to this Task!
	progID, _, err := m.pg.UpsertBountyProgram(&db.BountyProgram{
		ProgramKey: "bugcrowd:targetportal-entrypoints", Name: "TargetPortal", Platform: "bugcrowd",
		ProgramURL: "https://bugcrowd.com/engagements/targetportal", SubmissionURL: "https://bugcrowd.com/engagements/targetportal",
		OffersBounty: true, MaxBountyUSD: 10000, Currency: "USD", TrackerStatus: "hunting",
		InScopeAssets: []db.BountyScopeAsset{{Target: targetBaseURL, AssetType: "api", EligibleForBounty: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	huntSt := "hunting"
	_, _ = m.pg.UpdateBountyTracking(progID, &huntSt, &taskID, nil, nil, nil, nil)

	chatConv, err := m.pg.CreateConversation("auto", "TargetPortal Follow-up", nil)
	if err != nil {
		t.Fatal(err)
	}
	chatSSE, unsubSSE := globalConvStreamHub.subscribe(chatConv.ID)
	defer unsubSSE()
	if err := m.pg.UpsertTaskChatLink(taskID, chatConv.ID, "auto", initialFindingID); err != nil {
		t.Fatal(err)
	}

	// =========================================================================
	// ENTRY POINT 1A: FINDINGS PAGE -> "Continue Pentest" (`POST /api/chat?task=<id>`)
	// =========================================================================
	continueBody, _ := json.Marshal(map[string]any{
		"message": fmt.Sprintf("Continue comprehensive multi-agent penetration testing on **%s**.\n- @[finding#%d:Preliminary Export Endpoint Exposure] (medium, pending)\nCall set_goals and add_hint to revive Task #%s.", targetBaseURL, initialFindingID, taskObj.ID),
	})
	wCont := apiReq(http.MethodPost, "/api/chat?task="+taskObj.ID, string(continueBody))
	if wCont.Code != http.StatusAccepted {
		t.Fatalf("Findings -> Continue Pentest (POST /api/chat?task=%s) expected 202, got %d: %s", taskObj.ID, wCont.Code, wCont.Body.String())
	}

	// Wait for Main Agent -> Revived Task -> LLM Failover -> Planner -> 2 Parallel Workers -> Done!
	wave1Deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(wave1Deadline) {
		llmMu.Lock()
		ranWorkers := workerACalls > 0 && workerBCalls > 0
		llmMu.Unlock()
		if ranWorkers && s.resolvedTaskStatus(taskObj) == "done" {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if s.resolvedTaskStatus(taskObj) != "done" || mainAgentCalls == 0 || workerACalls == 0 || workerBCalls == 0 {
		t.Fatalf("Entry Point 1A (Findings -> Continue Pentest) failed to revive & complete Task #%s: status=%q mainAgent=%d planner=%d workerA=%d workerB=%d",
			taskObj.ID, s.resolvedTaskStatus(taskObj), mainAgentCalls, plannerCalls, workerACalls, workerBCalls)
	}

	// Trigger Reporter + Sync Bounty Tracker & Chat SSE!
	s.syncTaskChatUpdates()
	sc := &Scheduler{s: s, pg: m.pg}
	if triggers, terr := m.pg.ListEnabledTriggers(); terr == nil {
		sc.fireToolCalls(triggers)
	}

	// Wait for Reporter to save detailed Markdown report on the new Critical SQLi finding!
	var criticalFinding *db.DBFinding
	repDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(repDeadline) {
		allF, _ := m.pg.ListTaskFindingsAfter(taskID, initialFindingID)
		if len(allF) > 0 {
			if full, ferr := m.pg.GetFinding(allF[0].ID); ferr == nil && full != nil && strings.Contains(full.Report, "BEHEMOTH_ENTRYPOINTS_SQLI_ROOT") {
				criticalFinding = full
				break
			}
		}
		time.Sleep(120 * time.Millisecond)
	}
	if criticalFinding == nil {
		t.Fatal("expected Findings -> Continue Pentest workflow to record Critical SQLi finding and trigger Reporter report")
	}

	// Verify all connected infrastructure fired cleanly during Entry Point 1A!
	if primaryQuotaCalls.Load() == 0 {
		t.Fatal("expected LLM failover chain to try Primary profile before failing over to Backup")
	}
	if searxngQueries.Load() == 0 {
		t.Fatal("expected Multi-Engine Search (SearXNG) query from Worker")
	}
	if captchaCreateHits.Load() == 0 || captchaResultHits.Load() == 0 {
		t.Fatal("expected 2Captcha v2 Turnstile solve from Worker")
	}
	if !targetExploitConfirmed.Load() || upstreamProxyRequests.Load() == 0 {
		t.Fatalf("expected live proxied exploit confirmation (confirmed=%v upstreamProxy=%d)", targetExploitConfirmed.Load(), upstreamProxyRequests.Load())
	}
	if escalated, _ := m.pg.GetFinding(initialFindingID); escalated == nil || escalated.Severity != "high" || escalated.Status != "confirmed" {
		t.Fatalf("expected initial Finding #%d escalated to high/confirmed via update_finding, got %+v", initialFindingID, escalated)
	}
	if _, pmExploits, _ := pmGen.SearchArsenal("CVE-2026-88888", 10); len(pmExploits) == 0 {
		t.Fatal("expected newly verified PoC CVE-2026-88888 persisted in Patch Monitor Arsenal")
	}
	if bProg, _ := m.pg.GetBountyProgram(progID); bProg == nil || bProg.TrackerStatus != "bug_found" {
		t.Fatalf("expected Bounty Program #%d auto-promoted to bug_found, got %+v", progID, bProg)
	}
	if missing, _ := m.pg.MissingSkillStats(20); len(missing) > 0 {
		t.Fatalf("expected 0 missing skill calls, got %+v", missing)
	}
	sseEvents := 0
drainSSE:
	for {
		select {
		case fr := <-chatSSE:
			if fr.Event == "activity" {
				sseEvents++
			}
		case <-time.After(30 * time.Millisecond):
			break drainSSE
		}
	}
	if sseEvents < 2 {
		t.Fatalf("expected >=2 real-time SSE Task->Chat frames (finding + completion), got %d", sseEvents)
	}

	// =========================================================================
	// ENTRY POINT 1B: FINDINGS PAGE -> "Retest" (`POST /api/exploration/findings/{id}/retests`)
	// =========================================================================
	wRetest := apiReq(http.MethodPost, fmt.Sprintf("/api/exploration/findings/%d/retests", criticalFinding.ID), `{"notes":"Verify SQLi still reproduces after Continue Pentest"}`)
	if wRetest.Code != http.StatusAccepted && wRetest.Code != http.StatusOK {
		t.Fatalf("Findings -> Retest expected 202/200, got %d: %s", wRetest.Code, wRetest.Body.String())
	}
	retestDeadline := time.Now().Add(10 * time.Second)
	var sealedRetest *db.FindingRetest
	for time.Now().Before(retestDeadline) {
		list, _ := m.pg.ListFindingRetests(criticalFinding.ID)
		if len(list) > 0 && list[0].Status == "completed" {
			sealedRetest = list[0]
			break
		}
		time.Sleep(120 * time.Millisecond)
	}
	if sealedRetest == nil || sealedRetest.Verdict != "reproduced" || retesterCalls == 0 {
		t.Fatalf("expected Finding Retester to complete with verdict=reproduced, got %+v (calls=%d)", sealedRetest, retesterCalls)
	}

	// =========================================================================
	// ENTRY POINT 2: TRAFFIC PAGE (`/function/traffic`)
	//   - List captured exchanges (`GET /api/traffic`) & hosts (`GET /api/traffic/hosts`)
	//   - Inspect exchange (`GET /api/traffic/exchange?id=...`)
	//   - Link captured packet to Finding (`POST /api/exploration/findings/{id}/traffic`)
	//   - Verify Finding Report (`GET /api/report?task=...`) reflects bound evidence
	// =========================================================================
	wHosts := apiReq(http.MethodGet, "/api/traffic/hosts", "")
	if wHosts.Code != http.StatusOK || !strings.Contains(wHosts.Body.String(), "localhost") {
		t.Fatalf("Traffic -> GET /api/traffic/hosts expected localhost host, got %d: %s", wHosts.Code, wHosts.Body.String())
	}

	wTraffic := apiReq(http.MethodGet, "/api/traffic?q=/api/v1/export&limit=20", "")
	if wTraffic.Code != http.StatusOK {
		t.Fatalf("Traffic -> GET /api/traffic failed: %d %s", wTraffic.Code, wTraffic.Body.String())
	}
	var trafficResp struct {
		Exchanges []struct {
			ID     string `json:"id"`
			Method string `json:"method"`
			URL    string `json:"url"`
			Status int    `json:"status"`
		} `json:"exchanges"`
	}
	if err := json.Unmarshal(wTraffic.Body.Bytes(), &trafficResp); err != nil || len(trafficResp.Exchanges) == 0 {
		t.Fatalf("Traffic -> expected captured /api/v1/export exchange, got err=%v body=%s", err, wTraffic.Body.String())
	}
	capturedExchangeID := trafficResp.Exchanges[0].ID

	// Inspect raw request/response (what Traffic detail & Send-to-Repeater read!)
	wExch := apiReq(http.MethodGet, "/api/traffic/exchange?id="+url.QueryEscape(capturedExchangeID), "")
	if wExch.Code != http.StatusOK || !strings.Contains(wExch.Body.String(), "BEHEMOTH_ENTRYPOINTS_SQLI_ROOT") {
		t.Fatalf("Traffic -> GET /api/traffic/exchange?id=%s expected SQLi response body, got %d: %s", capturedExchangeID, wExch.Code, wExch.Body.String())
	}

	// Link captured packet from Traffic page directly to the Critical Finding!
	bindBody, _ := json.Marshal(map[string]any{
		"traffic_refs": []map[string]any{{
			"traffic_id": capturedExchangeID,
			"role":       "proof",
			"note":       "Captured live SQLi proof from Traffic page",
		}},
	})
	wBind := apiReq(http.MethodPost, fmt.Sprintf("/api/exploration/findings/%d/traffic", criticalFinding.ID), string(bindBody))
	if wBind.Code != http.StatusOK {
		t.Fatalf("Traffic -> Bind to Finding failed: %d %s", wBind.Code, wBind.Body.String())
	}

	// Verify Task Engagement Report HTTP endpoint (`GET /api/report?task=...`) renders cleanly with the bound evidence!
	wRep := apiReq(http.MethodGet, "/api/report?task="+taskObj.ID, "")
	if wRep.Code != http.StatusOK || !strings.Contains(wRep.Body.String(), "Critical SQLi in /api/v1/export") {
		t.Fatalf("Findings -> GET /api/report?task=%s failed or missing finding: %d", taskObj.ID, wRep.Code)
	}

	// =========================================================================
	// ENTRY POINT 3: REPEATER PAGE (`/function/repeater`)
	//   - Replay modified exploit request (`POST /api/repeater/send`) through
	//     MITM Recording Proxy + Upstream Proxy Pool -> Target
	//   - Verify replayed request is auto-captured back into Traffic (`GET /api/traffic`)
	//   - Bind replayed exchange back to Finding as `verification`
	// =========================================================================
	proxyBeforeRepeater := upstreamProxyRequests.Load()
	repeaterURL := "http://targetportal.e2e.local/api/v1/export?cf_token=2CAP_E2E_ENTRYPOINTS_TOKEN&id=1%27&repeater_probe=1"
	repPayload, _ := json.Marshal(map[string]any{
		"method":              "GET",
		"url":                 repeaterURL,
		"headers":             map[string]string{"X-Repeater-Verify": "behemoth-e2e"},
		"use_recording_proxy": true,
		"timeout_ms":          10000,
	})
	wRepeater := apiReq(http.MethodPost, "/api/repeater/send", string(repPayload))
	if wRepeater.Code != http.StatusOK {
		t.Fatalf("Repeater -> POST /api/repeater/send expected 200, got %d: %s", wRepeater.Code, wRepeater.Body.String())
	}
	var repOut repeaterSendResponse
	if err := json.Unmarshal(wRepeater.Body.Bytes(), &repOut); err != nil {
		t.Fatalf("decode repeater response: %v", err)
	}
	if repOut.Status != 200 || !strings.Contains(repOut.Body, "BEHEMOTH_ENTRYPOINTS_SQLI_ROOT") || repOut.Error != "" {
		t.Fatalf("Repeater -> unexpected replay result: %+v", repOut)
	}
	if repeaterHeaderHits.Load() == 0 {
		t.Fatal("Repeater -> custom header X-Repeater-Verify did not reach target server")
	}
	if upstreamProxyRequests.Load() <= proxyBeforeRepeater {
		t.Fatal("Repeater -> replayed request did NOT transit Upstream Proxy Pool!")
	}

	// Verify Repeater's replayed request landed automatically in MITM Traffic Capture!
	wTrafficAfterRep := apiReq(http.MethodGet, "/api/traffic?q=repeater_probe=1&limit=10", "")
	var trafficAfterRep struct {
		Exchanges []struct {
			ID string `json:"id"`
		} `json:"exchanges"`
	}
	_ = json.Unmarshal(wTrafficAfterRep.Body.Bytes(), &trafficAfterRep)
	if len(trafficAfterRep.Exchanges) == 0 {
		t.Fatalf("Repeater -> expected replayed request to be recorded in Traffic DB, got: %s", wTrafficAfterRep.Body.String())
	}
	repeaterExchangeID := trafficAfterRep.Exchanges[0].ID

	// Bind Repeater's verification packet back to the Finding!
	bindRepBody, _ := json.Marshal(map[string]any{
		"traffic_refs": []map[string]any{{
			"traffic_id": repeaterExchangeID,
			"role":       "verification",
			"note":       "Manual Repeater verification replay",
		}},
	})
	wBindRep := apiReq(http.MethodPost, fmt.Sprintf("/api/exploration/findings/%d/traffic", criticalFinding.ID), string(bindRepBody))
	if wBindRep.Code != http.StatusOK {
		t.Fatalf("Repeater -> Bind verification packet to Finding failed: %d %s", wBindRep.Code, wBindRep.Body.String())
	}
	wGetBind := apiReq(http.MethodGet, fmt.Sprintf("/api/exploration/findings/%d/traffic", criticalFinding.ID), "")
	if wGetBind.Code != http.StatusOK || !strings.Contains(wGetBind.Body.String(), capturedExchangeID) || !strings.Contains(wGetBind.Body.String(), repeaterExchangeID) {
		t.Fatalf("expected Finding #%d traffic evidence to contain both Traffic (%s) and Repeater (%s) packets, got: %s",
			criticalFinding.ID, capturedExchangeID, repeaterExchangeID, wGetBind.Body.String())
	}

	// =========================================================================
	// FINAL STAGE: COOLDOWN / CRON SCHEDULE WAVE 2 REVIVAL
	// =========================================================================
	cooldownJobsMu.Lock()
	jobs := s.loadCooldownResumeJobsLocked()
	for i := range jobs {
		if jobs[i].TaskID == taskID {
			jobs[i].NextFireUnix = time.Now().Unix() - 5
		}
	}
	_ = s.saveCooldownResumeJobsLocked(jobs)
	cooldownJobsMu.Unlock()

	sc.fireCooldownResumes()

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
		t.Fatalf("Cooldown Schedule Wave 2 did not revive & finish Task #%s (workerWave2Calls=%d, status=%q)",
			taskObj.ID, workerWave2Calls, s.resolvedTaskStatus(taskObj))
	}
}
