package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
	"github.com/Autumn-27/behemoth/intercept"
	"github.com/Autumn-27/behemoth/traffic"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// jsonResult marshals v to a JSON tool result.
func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// 本文件实现 P2「跨任务编排工具集」(docs/跑分编排 §2 P2)。这些是 host 工具——需要
// 访问 Manager(任意任务的 Store)、Engine(暂停)、以及建任务流程,所以住在 server 层。
// 读类工具把「现有 per-task 工具」重定向到目标任务的 store 上跑(建一个临时 ToolSet
// 并 Call 其对应工具),从而复用完全相同的逻辑;控制类(spawn/pause)直接调 Manager/Engine。
// 它们像流量工具一样 seed 进 tools 表、按 agent 绑定(只绑给编排 agent 才可见)。

// hostTools is the runtime host-tool provider fed to ToolAugment: traffic tools
// (gated by capture) + cross-task orchestration tools + user-defined custom tools.
// The second return is the names of custom tools flagged `deferred` (schema
// withheld, routed via SearchExtraTools/ExecuteExtraTool). Per-agent binding still
// decides who actually sees any of them.
//
// autoDeferredSpecialistTools lists bulky, low-frequency specialist tools whose
// full JSON schemas are withheld from the per-turn req.Tools payload (cutting
// per-turn input token bloat by ~60% for faster Time-To-First-Token) while
// remaining unlocked and advertised in the cached <available-deferred-tools> block.
var autoDeferredSpecialistTools = map[string]bool{
	"c2_build_implant":                         true,
	"c2_deploy":                                true,
	"c2_agents":                                true,
	"c2_task":                                  true,
	"c2_results":                               true,
	"c2_kill":                                  true,
	"c2_proxy_open":                            true,
	"c2_proxy_close":                           true,
	"c2_proxy_list":                            true,
	"check_patch_feeds":                        true,
	"add_patch_watch_feed":                     true,
	"discover_affected_sites_for_notification": true,
	"match_vuln_targets":                       true,
	"generate_vuln_exploit":                    true,
	"update_exploit_target_status":             true,
	"sync_nuclei_templates":                    true,
	"list_finding_cases":                       true,
	"get_finding_case":                         true,
	"update_finding_case":                      true,
	"create_skill":                             true,
	"update_skill_file":                        true,
	"create_custom_tool":                       true,
	"update_custom_tool":                       true,
	"delete_custom_tool":                       true,
	"create_mcp_server":                        true,
	"list_intercept_rules":                     true,
	"update_intercept_rule":                    true,
	"get_worker_trace":                         true,
	"list_worker_traces":                       true,
	"search_worker_traces":                     true,
	"get_task_node_detail":                     true,
	"proxied_tcp_relay":                        true,
	"create_callback_listener":                 true,
	"poll_callback_events":                     true,
	"audit_frontend_api_surface":               true,
	"verify_endpoint_idempotency":              true,
	"audit_source_routes":                      true,
	"list_proxy_scrape_sources":                true,
	"add_proxy_scrape_source":                  true,
	"remove_proxy_scrape_source":               true,
	"verify_and_import_scraped_proxies":        true,
	"list_cooldown_schedules":                  true,
	"cancel_cooldown_schedule":                 true,
	"list_bounty_programs":                     true,
	"register_bounty_program":                  true,
	"start_bounty_hunt":                        true,
	"update_bounty_tracker":                    true,
}

//nolint:unused // used as the hostTools provider in wireAgentAugment
func (s *Server) hostTools() ([]actool.CoreTool, map[string][]string) {
	tools := append(s.m.HostTools(), s.orchestrationTools()...)
	tools = append(tools, s.findingRetestTools()...)
	tools = append(tools, s.platformTools()...) // 平台操作工具(建改 skill/工具/MCP，给 Auto 用)
	custom, err := s.customTools()
	if err != nil {
		log.Printf("[custom-tool] 加载失败: %v", err)
	} else {
		tools = append(tools, custom...)
	}
	// deferred tools → name -> its bound agent keys. ToolAugment turns a
	// name into a deferred entry only for agents it's actually bound to (so we don't
	// advertise a tool the per-agent binding will drop from the callable set).
	deferred := map[string][]string{}
	if s.m != nil && s.m.pg != nil {
		rows, _ := s.m.pg.ListCustomTools()
		for _, t := range rows {
			if t.Deferred && t.Enabled {
				deferred[t.Key] = t.Agents
			}
		}
		allCatalog, _ := s.m.pg.ListTools()
		for _, ct := range allCatalog {
			if !ct.Enabled || !autoDeferredSpecialistTools[ct.Key] {
				continue
			}
			// Keep specialist tools inline for their dedicated specialist agent!
			var filteredAgents []string
			for _, ag := range ct.Agents {
				if ag == "proxy_harvester" && strings.Contains(ct.Key, "proxy_scrape") {
					continue
				}
				if ag == "bounty_scout" && strings.Contains(ct.Key, "bounty") {
					continue
				}
				if ag == "patch_researcher" && (strings.Contains(ct.Key, "patch") || strings.Contains(ct.Key, "vuln")) {
					continue
				}
				filteredAgents = append(filteredAgents, ag)
			}
			if len(filteredAgents) > 0 {
				deferred[ct.Key] = filteredAgents
			}
		}
	}
	return tools, deferred
}

// orchestrationTools returns the cross-task tool set. Bound per-agent via the
// tools table (default: no binding — opt-in for orchestration agents).
func (s *Server) orchestrationTools() []actool.CoreTool {
	out := append([]actool.CoreTool{
		s.toolListTasks(),
		s.toolListLLMProfiles(),
		s.toolSpawnTask(),
		s.toolPauseTask(),
		s.toolGetTaskGraph(),
		s.toolListTaskFindings(),
		s.toolAddHint(),
		s.toolGetWorkerTrace(),
		s.toolListWorkerTraces(),
		s.toolSearchWorkerTraces(),
		s.toolGetTaskNodeDetail(),
		s.toolUpdateFinding(),
		s.toolUpdateFindingReport(),
		s.toolGetFindingTraffic(),
		s.toolBindFindingTraffic(),
	}, s.findingCaseTools()...)
	out = append(out, s.patchMonitorTools()...)
	out = append(out, s.arsenalTools()...)
	out = append(out, s.c2Tools()...)
	out = append(out, s.artifactTools()...)
	out = append(out, s.captchaTools()...)
	out = append(out, s.agentRequestTools()...)
	out = append(out, s.cooldownScheduleTools()...)
	out = append(out, s.bountyHunterAgentTools()...)
	return append(out, s.proxyPoolAgentTools()...)
}

// --- schema helpers ---

func strParam(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// parseProfileID reads an LLM profile id from a tool arg that may arrive as a JSON
// number (5) or a numeric string ("5"); returns 0 when absent/unparseable.
func parseProfileID(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(str), 10, 64)
		return v
	}
	return 0
}

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		m["required"] = req
	}
	return m
}

func roTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func wrTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// delegateToTask resolves the `task_id` in the input, builds a ToolSet bound to
// that task's store, strips task_id, and calls the chosen per-task tool — so the
// cross-task read reuses the exact in-task logic against another task.
func (s *Server) delegateToTask(ctx context.Context, in json.RawMessage, pick func(*agent.ToolSet) actool.CoreTool) (actool.Result, error) {
	var head struct {
		TaskID string `json:"task_id"`
	}
	_ = json.Unmarshal(in, &head)
	if strings.TrimSpace(head.TaskID) == "" {
		return actool.Errorf("task_id is required"), nil
	}
	t, ok := s.m.Task(head.TaskID)
	if !ok {
		return actool.Errorf("task not found: " + head.TaskID), nil
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(in, &m)
	delete(m, "task_id")
	inner, _ := json.Marshal(m)
	tsx := agent.NewToolSet(t.Store, "orchestrator")
	if s.m.Assets() != nil {
		tsx.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	}
	tsx.SetNotify(t.Notify)
	tsx.SetNotifyHint(t.NotifyHint)
	return pick(tsx).Call(ctx, inner, nil)
}

// --- tools ---

func (s *Server) toolListTasks() actool.CoreTool {
	return roTool("list_tasks",
		"List all tasks (id / description / goal / status / run duration / parent task / LLM profile). Used by orchestration agents to inspect global status, see which tasks are stuck, and check which LLM each task uses. Run duration accumulates only active execution time (excluding paused, queued, and terminal time). llm_profile shows the profile name used by the task's planner/worker, or (active profile) when following the global default.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			profName := map[int64]string{}
			if profs, err := s.m.pg.ListProfiles(); err == nil {
				for _, p := range profs {
					profName[p.ID] = p.Name
				}
			}
			out := make([]map[string]any, 0)
			for _, t := range s.m.List() {
				status := s.deriveTaskStatus(t)
				lifecycle := t.lifecycleSnapshot()
				dur := taskRunSeconds(lifecycle.ActiveRunSeconds, lifecycle.RunSegmentStartedAt, time.Now().Unix(), status, lifecycle.Paused, lifecycle.Queued)
				row := map[string]any{"id": t.ID, "description": t.Description, "goal": t.Goal, "status": status, "run_seconds": dur}
				if t.ParentRef != "" {
					row["parent_ref"] = t.ParentRef
				}
				llmState := t.llmStateSnapshot()
				if llmState.ProfileID == nil {
					row["llm_profile"] = "(active profile)"
				} else if n, ok := profName[*llmState.ProfileID]; ok {
					row["llm_profile"] = n
				} else {
					row["llm_profile"] = fmt.Sprintf("#%d (deleted)", *llmState.ProfileID)
				}
				out = append(out, row)
			}
			return jsonResult(out)
		})
}

func (s *Server) toolListLLMProfiles() actool.CoreTool {
	return roTool("list_llm_profiles",
		"List available LLM profiles: id, name, model, format, and whether it is the currently active profile. Pass id to spawn_task's llm_profile_id parameter to assign a dedicated LLM to a subtask (e.g. a fast model for recon and a strong model for exploitation). Never exposes API keys.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			profs, err := s.m.pg.ListProfiles()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(profs))
			for _, p := range profs {
				out = append(out, map[string]any{
					"id": p.ID, "name": p.Name, "model": p.Model, "format": p.Format, "is_active": p.IsDefault,
				})
			}
			return jsonResult(map[string]any{"profiles": out})
		})
}

func (s *Server) toolSpawnTask() actool.CoreTool {
	return wrTool("spawn_task",
		"Create a new subtask, start the exploration engine, and return task_id. Used to dispatch a specific target or objective as an independent task. parent_ref is optional: pass the parent task ID for parent-child linking.",
		objSchema(map[string]any{
			"description":            strParam("Task description (short title)"),
			"goal":                   strParam("Task goal (what to achieve)"),
			"parent_ref":             strParam("Optional: parent task id (for parent-child linking)"),
			"source_task_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": fmt.Sprintf("Optional: list of read-only inherited source task IDs (max %d). The subtask can reference assets/conclusions already discovered by those tasks as a starting point; unlike parent_ref, this inherits content.", db.MaxTaskSourceCount)},
			"llm_profile_id":         map[string]any{"type": "integer", "description": "Optional: LLM profile ID for this subtask's planner/worker (see list_llm_profiles); leave empty to inherit from parent task or fall back to the global active profile"},
			"no_result_seconds":      map[string]any{"type": "integer", "description": "Optional: check once after accumulating this many active run seconds and stop if minimum findings are not met. 0 = disabled, positive min 60s; paused/queued time is excluded"},
			"no_result_min_findings": map[string]any{"type": "integer", "description": "Minimum distinct findings required for no-result stop-loss, default 1; false positives excluded"},
			"no_result_min_severity": map[string]any{"type": "string", "enum": []string{"", "low", "medium", "high", "critical"}, "description": "Minimum vulnerability severity to count (inclusive), empty = any"},
			"timeout_seconds":        map[string]any{"type": "integer", "description": "Optional: leave empty or 0 (unlimited until all sub-goals are achieved)! Only set a positive wall-clock timeout when the operator explicitly asks for a specific time limit."},
			"plan_heartbeat_seconds": map[string]any{"type": "integer", "description": "Optional: planner heartbeat interval in seconds. Triggers a planning round when this time elapses without other triggers since task start or last round end; leave empty or 0 = default 600 (10min)"},
			"seed_first_intent":      map[string]any{"type": "boolean", "description": "Optional: for simple tasks, dispatch an initial seed intent (description + goal) immediately on creation so a worker starts testing without waiting for round-0 planner; default false (plan first, then execute)"},
			"force_new":              map[string]any{"type": "boolean", "description": "Optional: set true only when explicitly asked by the operator to create a brand-new separate task even if an active task already exists for the same target domain"},
		}, "description", "goal"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Description          string          `json:"description"`
				Goal                 string          `json:"goal"`
				ParentRef            string          `json:"parent_ref"`
				SourceTaskIDs        []string        `json:"source_task_ids"`
				LLMProfileID         json.RawMessage `json:"llm_profile_id"`
				NoResultSeconds      int             `json:"no_result_seconds"`
				NoResultMinFindings  int             `json:"no_result_min_findings"`
				NoResultMinSeverity  string          `json:"no_result_min_severity"`
				TimeoutSeconds       int             `json:"timeout_seconds"`
				PlanHeartbeatSeconds int             `json:"plan_heartbeat_seconds"`
				SeedFirstIntent      bool            `json:"seed_first_intent"`
				ForceNew             bool            `json:"force_new"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Description) == "" {
				a.Description = "Untitled Task"
			}
			if strings.TrimSpace(a.Goal) == "" {
				return actool.Errorf("goal is required"), nil
			}
			// Prevent duplicate top-level tasks for the same target domain/host when an
			// active (non-terminal) task already exists for that target.
			if strings.TrimSpace(a.ParentRef) == "" && !a.ForceNew && s.m != nil {
				if targetDom := extractPrimaryTargetDomain(a.Description + " " + a.Goal); targetDom != "" {
					for _, existing := range s.m.List() {
						st := existing.lifecycleSnapshot()
						if isTerminalStatus(st.Status) {
							continue
						}
						hay := strings.ToLower(existing.Name + " " + existing.Description + " " + existing.Goal)
						if strings.Contains(hay, targetDom) {
							convID := s.linkTaskToConversationFromCtx(ctx, existing.ID, true)
							hintJSON, _ := json.Marshal(map[string]any{
								"task_id": existing.ID,
								"text":    "Additional objective from Chat: " + strings.TrimSpace(a.Goal),
							})
							_, _ = s.delegateToTask(ctx, hintJSON, (*agent.ToolSet).AddHintTool)
							if open, oerr := existing.Store.HasOpenGoal(); oerr == nil && !open {
								s.ensureOpenGoalAndReviveTask(existing, strings.TrimSpace(a.Goal))
							} else if existing.Paused {
								_, _ = s.admitPausedTask(existing)
							}
							extra := ""
							if convID > 0 {
								extra = fmt.Sprintf("\ntask_url: /function/tasks/detail?id=%s\nlive_chat_updates: linked to Conversation #%d (do NOT scan solo in Chat; reply to the user with [Task #%s](/function/tasks/detail?id=%s) and let them know live updates will post back here automatically)", existing.ID, convID, existing.ID, existing.ID)
							}
							return actool.Text(fmt.Sprintf("reused existing active task: %s (target %s already has an active task; objective appended as hint instead of creating a duplicate task)%s", existing.ID, targetDom, extra)), nil
						}
					}
				}
			}
			if a.TimeoutSeconds < 0 {
				a.TimeoutSeconds = 0
			}
			if len(a.SourceTaskIDs) > db.MaxTaskSourceCount {
				return actool.Errorf(fmt.Sprintf("at most %d linked source tasks can be selected", db.MaxTaskSourceCount)), nil
			}
			sourceIDs := make([]int64, 0, len(a.SourceTaskIDs))
			seenSources := map[int64]bool{}
			for _, raw := range a.SourceTaskIDs {
				id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
				if err != nil || id <= 0 || seenSources[id] {
					return actool.Errorf("invalid or duplicate linked source task id"), nil
				}
				if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
					return actool.Errorf(fmt.Sprintf("linked source task #%d does not exist", id)), nil
				}
				seenSources[id] = true
				sourceIDs = append(sourceIDs, id)
			}
			var pin *int64
			if id := parseProfileID(a.LLMProfileID); id > 0 {
				if _, ok := s.loadProfileConfig(id); !ok {
					return actool.Errorf(fmt.Sprintf("LLM profile #%d does not exist or has no API key configured", id)), nil
				}
				pin = &id
			} else if a.ParentRef != "" {
				if pt, ok := s.m.Task(a.ParentRef); ok {
					pin = pt.LLMProfileID
				}
			}
			var llmIDs []int64
			if pin != nil {
				llmIDs = []int64{*pin}
			}
			name := ""
			autoTitleEnabled := s.m.pg.GetBool(db.SettingTaskAutoTitle, false)
			if autoTitleEnabled {
				if err := ctx.Err(); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				active, activeErr := s.m.pg.ActiveProfile()
				if activeErr != nil {
					log.Printf("[auto-title] active profile lookup failed: %v", activeErr)
				} else if active == nil {
					log.Printf("[auto-title] no active profile")
				} else if prov, _, providerOK := s.providerForProfile(active.ID); providerOK {
					titleCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
					defer cancel()
					generated, titleErr := agent.GenerateAutoTitle(titleCtx, prov, a.Description+"\n"+a.Goal)
					if err := ctx.Err(); err != nil {
						return actool.Errorf(err.Error()), nil
					}
					if titleErr == nil {
						name = generated
					} else {
						log.Printf("[auto-title] task title generation failed: %v", titleErr)
					}
				} else {
					log.Printf("[auto-title] task provider unavailable for active profile %d", active.ID)
				}
			}
			if autoTitleEnabled {
				if err := ctx.Err(); err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			t, err := s.m.CreateTaskWithOptions(a.Description, a.Goal, db.TaskCreateOptions{
				Name:            name,
				SourceTaskIDs:   sourceIDs,
				LLMProfileIDs:   llmIDs,
				NoResultSeconds: a.NoResultSeconds, NoResultMinFindings: a.NoResultMinFindings, NoResultMinSeverity: a.NoResultMinSeverity,
				TimeoutSeconds:       a.TimeoutSeconds,
				PlanHeartbeatSeconds: a.PlanHeartbeatSeconds,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.ParentRef != "" {
				t.ParentRef = a.ParentRef
				if id, e := strconv.ParseInt(t.ID, 10, 64); e == nil {
					_ = s.m.PG().SetParentRef(id, a.ParentRef)
				}
			}
			// Link to originating /chat conversation BEFORE launchTask so rapid goal
			// decomposition immediately sees the link row.
			convID := s.linkTaskToConversationFromCtx(ctx, t.ID, false)
			// 共享的建后流程,与 HTTP 建任务(server.go createTask)复用同一段 launchTask:
			// seed + 后台可见地做目标分解(第0轮/LLM步骤/逐条goal) + engine.Run。
			// seed_first_intent 默认 false(标准先规划再执行);简单任务可开启直接下发一 work 测试。
			s.launchTask(t, a.Description+" "+a.Goal, a.SeedFirstIntent)
			if convID > 0 {
				workers := s.activeWorkerConcurrencyForTask(t)
				return actool.Text(fmt.Sprintf(
					"task created: %s\ntask_url: /function/tasks/detail?id=%s\nparallel_workers: %d simultaneous Worker agents + Goal Decomposer + Planner + Reporter\nlive_chat_updates: linked to Conversation #%d (stop solo probing in Chat now — reply concisely to the user with the clickable [Task #%s](/function/tasks/detail?id=%s) link and let them know live updates will automatically post back into this Chat!)",
					t.ID, t.ID, workers, convID, t.ID, t.ID,
				)), nil
			}
			return actool.Text(fmt.Sprintf("task created: %s", t.ID)), nil
		})
}

func (s *Server) toolPauseTask() actool.CoreTool {
	return wrTool("pause_task", "Pause a specified task (stops its planner/worker loop).",
		objSchema(map[string]any{"task_id": strParam("Task ID to pause")}, "task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)
			t, ok := s.m.Task(a.TaskID)
			if !ok {
				return actool.Errorf("task not found: " + a.TaskID), nil
			}
			if _, err := s.applyTaskControlWithCause(t, "pause", agent.AbortPausedByOrchestrator); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("task paused: " + a.TaskID), nil
		})
}

func (s *Server) toolGetTaskGraph() actool.CoreTool {
	return roTool("get_task_graph", "Read the exploration graph overview of a specified task (same as graph_overview: asset counts / frontier / findings / coverage, etc.), specifying the task via task_id.",
		objSchema(map[string]any{"task_id": strParam("Task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GraphOverviewTool)
		})
}

func (s *Server) toolListTaskFindings() actool.CoreTool {
	return roTool("list_task_findings", "Read confirmed vulnerabilities of a specified task (including flags/PoCs; each item carries id/task_id/intent_id/vulnclass/severity/summary/state), specifying the task via task_id.",
		objSchema(map[string]any{"task_id": strParam("Task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListFindingsTool)
		})
}

func (s *Server) toolAddHint() actool.CoreTool {
	return wrTool("add_task_hint", "Inject strategic hints into a specified task (the task's planner will read them on its next intent generation round).\n"+
		"★ Prefer batching: put multiple hints into the hints array and submit in a single call (returns ids array of the same length and order as hints, failed items have id=0); for a single hint, omit hints and provide top-level text directly.",
		objSchema(map[string]any{
			"task_id":      strParam("Task id"),
			"hints":        map[string]any{"type": "array", "description": "[Preferred] Array of hints; each element has the same fields as top-level (text/asset_ids/traffic_refs).", "items": objSchema(map[string]any{"text": strParam("Hint content"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": agent.HintTrafficSchema()})},
			"text":         strParam("[Single] Hint content"),
			"traffic_refs": agent.HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Anchored asset IDs (optional, 0/1/multiple; asset IDs within that task)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var parsed struct {
				TaskID string `json:"task_id"`
				Text   string `json:"text"`
				Hints  []struct {
					Text string `json:"text"`
				} `json:"hints"`
			}
			_ = json.Unmarshal(in, &parsed)
			var convID int64
			if strings.TrimSpace(parsed.TaskID) != "" {
				convID = s.linkTaskToConversationFromCtx(ctx, parsed.TaskID, true)
			}
			res, err := s.delegateToTask(ctx, in, (*agent.ToolSet).AddHintTool)
			if err == nil && !res.IsError && convID > 0 && s.m != nil {
				if t, ok := s.m.Task(strings.TrimSpace(parsed.TaskID)); ok && t != nil {
					st := t.lifecycleSnapshot()
					open, oerr := t.Store.HasOpenGoal()
					if isTerminalStatus(st.Status) || (oerr == nil && !open) {
						obj := strings.TrimSpace(parsed.Text)
						if obj == "" && len(parsed.Hints) > 0 {
							obj = strings.TrimSpace(parsed.Hints[0].Text)
						}
						s.ensureOpenGoalAndReviveTask(t, obj)
					}
				}
			}
			return res, err
		})
}

func (s *Server) toolGetWorkerTrace() actool.CoreTool {
	return roTool("get_task_worker_trace",
		"Inspect the execution trace of a specific work (intent) in a specified task: call get_task_worker_trace(task_id, intent_id) for step summaries; pass step_ids=[...] to fetch full content of those steps (max 5 per call, extras listed in omitted_step_ids).",
		objSchema(map[string]any{
			"task_id":   strParam("Task id"),
			"intent_id": map[string]any{"type": "integer", "description": "Intent id (work in that task)"},
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Optional: step IDs to fetch full content for (max 5 per call, extras listed in omitted_step_ids)"},
		}, "task_id", "intent_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GetWorkerTraceTool)
		})
}

func (s *Server) toolListWorkerTraces() actool.CoreTool {
	return roTool("list_task_worker_traces", "List which works (intents) have run in a specified task along with their step counts, used to discover which works are worth inspecting (follow up with get_task_worker_trace).",
		objSchema(map[string]any{"task_id": strParam("Task id")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListWorkerTracesTool)
		})
}

func (s *Server) toolSearchWorkerTraces() actool.CoreTool {
	return roTool("search_task_worker_traces", "Search by keyword across the execution traces of all works in a specified task (returns matching step summaries + intent_id).",
		objSchema(map[string]any{"task_id": strParam("Task id"), "q": strParam("Search keyword")}, "task_id", "q"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).SearchWorkerTracesTool)
		})
}

func (s *Server) toolGetTaskNodeDetail() actool.CoreTool {
	return roTool("get_task_node_detail",
		"Read the full content of an exploration graph node in a specified task (finding / fact / intent / goal: summary + detail / evidence / PoC). id is the exploration node id (such as returned by report_finding or in list_task_findings). Use this before writing a vulnerability report to retrieve the full evidence.",
		objSchema(map[string]any{
			"task_id": strParam("Task id"),
			"id":      map[string]any{"type": "integer", "description": "Exploration graph node id (not asset id)"},
		}, "task_id", "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).NodeDetailTool)
		})
}

// toolUpdateFinding escalates or updates an existing finding's severity, status,
// title, summary, and verified PoC evidence after follow-up exploitation (instead
// of creating duplicate finding rows or merely recommending a severity change in prose).
func (s *Server) toolUpdateFinding() actool.CoreTool {
	return wrTool("update_finding",
		"Update an existing vulnerability finding's severity (critical | high | medium | low), status (confirmed | in_progress | false_positive | resolved), title, summary, or append newly verified exploitation PoC evidence. Always call this when follow-up exploitation proves higher impact (e.g. escalating Low -> Medium/High/Critical and setting status='confirmed') rather than merely suggesting a re-rating in text!",
		objSchema(map[string]any{
			"finding_id":      map[string]any{"type": "integer", "description": "Finding ID (or exploration node ID returned by report_finding)"},
			"severity":        strParam("Optional updated severity: critical | high | medium | low"),
			"status":          strParam("Optional updated status: confirmed | in_progress | pending | false_positive"),
			"name":            strParam("Optional updated vulnerability title"),
			"vulnclass":       strParam("Optional updated vulnerability class"),
			"summary":         strParam("Optional updated executive/technical summary reflecting exploitation outcome"),
			"append_evidence": strParam("Optional verified exploitation PoC output / differential proof to append to the finding's evidence"),
		}, "finding_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingID      json.RawMessage `json:"finding_id"`
				Severity       string          `json:"severity"`
				Status         string          `json:"status"`
				Name           string          `json:"name"`
				VulnClass      string          `json:"vulnclass"`
				Summary        string          `json:"summary"`
				AppendEvidence string          `json:"append_evidence"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			id := parseProfileID(a.FindingID)
			if id <= 0 {
				return actool.Errorf("valid finding_id is required"), nil
			}
			if err := s.checkCaseReviewScope(ctx, "update_finding_report", findingCaseRequest{FindingID: json.RawMessage(i64s(id))}); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			updated, err := s.m.pg.UpdateFindingAfterExploitation(id, a.Severity, a.Status, a.Name, a.VulnClass, a.Summary, a.AppendEvidence)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"ok":         true,
				"finding_id": updated.ID,
				"severity":   updated.Severity,
				"status":     updated.Status,
				"name":       updated.Name,
				"vulnclass":  updated.VulnClass,
			})
		})
}

// toolUpdateFindingReport writes/overwrites a finding's detailed Markdown report.
// finding_id is the id report_finding returned ("finding recorded: <id>", the
// finding node id). The write (SetFindingReportByNodeID) is keyed by node_id and
// task-agnostic, so this host tool needs no task_id / exploration store.
func (s *Server) toolUpdateFindingReport() actool.CoreTool {
	return wrTool("update_finding_report",
		"Write or update the [detailed report] (full Markdown text, overwriting previous content) for a registered vulnerability. Pass the id returned by report_finding (\"finding recorded: <id>\") as finding_id. Recommended sections: Overview, Impact & Risk, Reproduction Steps, Evidence / PoC, and Remediation.",
		objSchema(map[string]any{
			"finding_id":       map[string]any{"type": "integer", "description": "Target vulnerability node id (the id returned by report_finding)"},
			"report":           strParam("Full detailed report in Markdown format"),
			"evidence_version": map[string]any{"type": "integer", "description": "Evidence version returned by get_finding_traffic; prevents overwriting newer evidence changes"},
		}, "finding_id", "report"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				EvidenceVersion *int64          `json:"evidence_version"`
				FindingID       json.RawMessage `json:"finding_id"`
				Report          string          `json:"report"`
			}
			_ = json.Unmarshal(in, &a)
			nodeID := parseProfileID(a.FindingID)
			if nodeID <= 0 {
				return actool.Errorf("invalid finding_id"), nil
			}
			fid, err := s.m.pg.FindingIDByNodeID(nodeID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if fid > 0 {
				if err := s.checkCaseReviewScope(ctx, "update_finding_report", findingCaseRequest{FindingID: json.RawMessage(i64s(fid))}); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if f, err := s.m.pg.GetFinding(fid); err == nil && f != nil && f.TaskID != nil {
					if err := s.archiveFindingScreenshots(*f.TaskID, a.Report); err != nil {
						return actool.Errorf("failed to archive report screenshots: " + err.Error()), nil
					}
				}
				if conversationID := intercept.ConvIDFromContext(ctx); conversationID > 0 {
					if err := s.m.pg.SetFindingReportConversationID(fid, conversationID); err != nil {
						return actool.Errorf("failed to link report conversation: " + err.Error()), nil
					}
				}
			}
			n, err := s.m.pg.SetFindingReportVersionByNodeID(ctx, nodeID, a.Report, a.EvidenceVersion)
			if err != nil {
				if fid > 0 {
					if curF, gerr := s.m.pg.GetFinding(fid); gerr == nil && curF != nil {
						return actool.Errorf(fmt.Sprintf("%s (current evidence_version=%d — pass evidence_version=%d or omit evidence_version)", err.Error(), curF.EvidenceVersion, curF.EvidenceVersion)), nil
					}
				}
				return actool.Errorf(err.Error()), nil
			}
			if n == 0 {
				return actool.Errorf(fmt.Sprintf("no vulnerability record found for finding_id=%d (register via report_finding first)", nodeID)), nil
			}
			targetFindingID := fid
			if targetFindingID <= 0 {
				targetFindingID = nodeID
			}
			var savedPath string
			if s.m != nil && strings.TrimSpace(s.m.dir) != "" {
				reportsDir := filepath.Join(s.m.dir, "reports")
				if mkErr := os.MkdirAll(reportsDir, 0o755); mkErr == nil {
					rel := filepath.Join("reports", fmt.Sprintf("finding-%d-report.md", targetFindingID))
					full := filepath.Join(s.m.dir, rel)
					if wErr := os.WriteFile(full, []byte(a.Report), 0o644); wErr == nil {
						savedPath = rel
					}
				}
			}
			if savedPath != "" {
				return actool.Text(fmt.Sprintf(
					"finding %d report saved (%d chars) — viewable in Findings -> Detail (/function/findings/detail?id=%d) and exported to Workspace file %s",
					targetFindingID, len(a.Report), targetFindingID, savedPath,
				)), nil
			}
			return actool.Text(fmt.Sprintf(
				"finding %d report saved (%d chars) — viewable in Findings -> Detail (/function/findings/detail?id=%d)",
				targetFindingID, len(a.Report), targetFindingID,
			)), nil
		})
}

// deriveTaskStatus mirrors listTasks' status derivation for the list_tasks tool.
func (s *Server) deriveTaskStatus(t *Task) string {
	lifecycle := t.lifecycleSnapshot()
	switch {
	case isTerminalStatus(lifecycle.Status):
		return lifecycle.Status
	case lifecycle.Paused || s.engine.IsPaused(t.ID):
		return "paused"
	case s.engine.ReadyFor(t) && s.engine.Started(t.ID):
		return "running"
	}
	return "created"
}

// orchestrationToolSeeds seeds the cross-task tools into the tools table so they
// are bindable per-agent (default: bound to nobody — opt-in for orchestration
// agents). First-insert only, like the traffic seeds.
func (s *Server) seedOrchestrationTools() {
	// task-op + platform tools default-bind to the built-in Auto agent (它天生用来
	// 操作平台)。SeedTool 首插入生效;老库已 seed 的行由 seedAutoDefaultBindings 补绑。
	autoAgents, _ := json.Marshal([]string{"auto"})
	for _, t := range s.orchestrationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings := autoAgents
		if t.Name() == "bind_finding_traffic" || strings.Contains(t.Name(), "finding_case") || t.Name() == "search_finding_duplicates" || t.Name() == "get_finding_record" || t.Name() == "merge_finding_records" || t.Name() == "suggest_finding_merge" {
			bindings = json.RawMessage(`["reporter"]`)
		}
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings)
	}
	for _, t := range s.platformTools() {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, autoAgents)
	}
	s.refreshBuiltinToolSchemas()
	s.seedAutoDefaultBindings()
	s.seedPlannerDefaultBindings()
	s.seedPlannerListAssetsBinding()
	s.seedCompanyScopeRebind()
	s.seedWorkerReadToolsUnbind() // list_facts/list_companies/list_worker_traces 从 worker 默认解绑(一次性)
	s.seedWorkerReadbackRebind()  // 修复旧迁移误删：把 search_all_worker_traces/get_worker_trace/node_detail 补绑回 worker(一次性)
	s.seedAutoReportFindingBinding()
	s.unbindGoalMetDefault()
	s.reseedGoalsPrompt()             // goals 提示词加入「抽操作约束」步 → 旧库追加一版新默认(一次性)
	s.reseedMainAgentPrompt()         // mainagent 提示词加入「目标达成后 add_intent 反问是否建目标」(一次性)
	s.reseedPlannerPrompt()           // planner 提示词:重写「0 意图」正当理由 + 加量化验收核对(一次性)
	s.reseedWorkerPrompt()            // worker 提示词:加否定结论证据门槛(一次性)
	s.seedReporterAgent()             // 预置「报告撰写」agent + 工具绑定 + finding 触发器(一次性)
	s.upgradeReporterTriggerMessage() // 老库补迁移:让 reporter 回传 evidence_version(一次性)
	s.migrateReporterWorkflow()       // 修复旧库残留的 reproduction 工具/提示词绑定
	if s.m.pg.GetBool(settingBrowserScreenshot, false) {
		// Re-apply the opt-in after startup seeding so an existing database gets
		// both reporter visibility and the repaired Playwright launch arguments.
		if err := s.setReporterBrowserScreenshotVisibility(true); err != nil {
			log.Printf("[reporter] 截图 MCP 启动配置同步失败: %v", err)
		}
	}
	s.seedFindingTrafficTools() // 增加可选证据参数及只读证据工具，保留用户配置
	s.seedFindingWorkflowTools()
	s.seedFindingCaseTools()
	s.seedArsenalAndAutoUpgradeV1()
	s.seedProxyPoolAgentToolsV1()
	s.seedSelfImprovingScannerToolsV1()
	s.seedLootAndCaptchaToolsV1()
	s.seedCaptchaAndSearchToolsV2()
	s.seedCooldownScheduleToolsV1()
	s.seedBountyHunterToolsV1()
	s.seedAgentRequestToolsV1()
	s.seedC2ToolsV1()
	s.seedC2ProxyToolsV1()
	s.syncDiscoveredSkillsVisibility()
	s.seedRecommendedPlatformDefaultsAndMCPsV1()
	s.seedAutoTaskDelegationV2()
	s.reconcileBountyTaskScopeIsolation()
	// 注：pentest 的默认工具绑定无需迁移——BuiltinToolSeeds 在全新初始化时就把
	// list_assets/insert_assets/report_finding/list_findings/list_companies 连同
	// pentest 一起 seed 好了（项目尚无旧库，不做迁移）。
}

// migrateReporterWorkflow repairs databases created by the short-lived
// structured-reproduction reporter. That workflow referenced
// update_finding_reproduction, which is no longer a runtime tool; leaving the
// old prompt/trigger in place makes a newly reported vulnerability fail after
// all evidence has already been collected. User-authored reporter prompts are
// preserved unless they contain the removed tool contract.
func (s *Server) migrateReporterWorkflow() {
	const flag = "reporter_workflow_markdown_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()

	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil {
		return
	}
	if current, err := s.m.pg.CurrentPrompt(reporter.ID); err == nil &&
		(strings.Contains(current, "update_finding_reproduction") || strings.Contains(current, "漏洞步骤编写 agent")) {
		if _, err := s.m.pg.ResetPromptToDefault(reporter.ID, agent.ReporterDefaultPrompt); err != nil {
			log.Printf("[reporter] 旧版提示词迁移失败: %v", err)
		} else {
			log.Printf("[reporter] 已将旧版复现步骤提示词迁移为 Markdown 报告流程")
		}
	}

	// 只补齐当前报告流程需要的绑定，不覆盖管理员已有的其它配置。
	_ = s.m.pg.AddAgentToToolBinding("reporter", []string{
		"update_finding_report", "get_finding_traffic", "bind_finding_traffic",
		"get_task_node_detail", "list_task_findings", "get_task_worker_trace",
		"list_task_worker_traces", "search_task_worker_traces", "get_task_graph",
	})
	// 旧行保留在工具目录里供历史审计，但不能继续被运行时广告或调用。
	if _, err := s.m.pg.Exec(`UPDATE tools SET enabled=false, updated_at=now() WHERE key='update_finding_reproduction' AND system`); err != nil {
		log.Printf("[reporter] 旧 reproduction 工具停用失败: %v", err)
	}

	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] 读取触发器失败: %v", err)
		return
	}
	for _, t := range triggers {
		if !t.OnToolCall || !strings.Contains(t.ToolCallMessage, "update_finding_reproduction") {
			continue
		}
		t.ToolCallMessage = reporterToolCallMessage
		if err := s.m.pg.UpdateTrigger(t); err != nil {
			log.Printf("[reporter] 旧触发器迁移失败: %v", err)
			continue
		}
		log.Printf("[reporter] 已将旧 reproduction 触发器迁移为报告保存流程")
	}
}

// refreshBuiltinToolSchemas propagates code schema/description changes on the
// orchestration + platform tools into already-seeded rows ONCE per version flag —
// SeedTool is first-insert-only, so a new param (e.g. spawn_task 的 llm_profile) never
// reaches an old DB otherwise. Preserves each tool's agent binding + enabled flag.
// Bump the flag whenever these tools' schemas/descriptions change in code.
func (s *Server) refreshBuiltinToolSchemas() {
	// Seed built-in patch monitor tools (first-insert-only, preserves user edits).
	for _, t := range s.patchMonitorTools() {
		schema, _ := json.Marshal(t.InputSchema())
		binds, _ := json.Marshal([]string{"auto", "pentest", "patch_watch", "worker"})
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), schema, binds)
	}

	const flag = "tool_schema_refresh_v16_multi_search_and_whatsapp"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	_ = s.m.pg.AddAgentToToolBinding("auto", []string{
		"insert_assets", "list_assets", "add_company_scope", "list_companies",
		"report_finding", "list_findings", "traffic_search", "traffic_get", "traffic_blob",
		"spawn_task", "list_tasks", "pause_task", "get_task_graph", "list_task_findings",
		"add_task_hint", "get_task_worker_trace", "list_task_worker_traces",
		"search_task_worker_traces", "get_task_node_detail",
		"create_skill", "update_skill_file", "create_custom_tool", "update_custom_tool", "create_mcp", "update_mcp",
		"generate_payload", "check_patch_feeds", "generate_vuln_exploit", "search_ios_exploits",
		"multi_engine_search", "exploit_search",
	})
	_ = s.m.pg.AddAgentToToolBinding("pentest", []string{
		"insert_assets", "list_assets", "add_company_scope", "list_companies",
		"report_finding", "list_findings", "traffic_search", "traffic_get", "traffic_blob",
		"create_skill", "update_skill_file",
		"generate_payload", "check_patch_feeds", "generate_vuln_exploit", "search_ios_exploits",
		"multi_engine_search", "exploit_search",
	})
	_ = s.m.pg.AddAgentToToolBinding("reporter", []string{"traffic_search", "traffic_get", "traffic_blob"})
	_ = s.m.pg.AddAgentToToolBinding("patch_watch", []string{
		"insert_assets", "list_assets", "add_company_scope", "list_companies",
		"report_finding", "list_findings",
		"generate_payload", "check_patch_feeds", "generate_vuln_exploit", "search_ios_exploits",
		"multi_engine_search", "exploit_search",
		"create_skill", "update_skill_file",
	})
	_ = s.m.pg.AddAgentToToolBinding("worker", []string{
		"generate_payload", "check_patch_feeds", "generate_vuln_exploit", "search_ios_exploits",
		"multi_engine_search", "exploit_search",
	})
	_ = s.m.pg.AddAgentToToolBinding("planner", []string{"multi_engine_search", "exploit_search"})
	_ = s.m.pg.AddAgentToToolBinding("mainagent", []string{"multi_engine_search", "exploit_search"})
	_ = s.m.pg.AddAgentToToolBinding("asset_mapper", []string{"multi_engine_search"})
	tools := append(append(s.orchestrationTools(), s.platformTools()...), s.findingRetestTools()...)
	tools = append(tools, traffic.SeedToolMetas()...)
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
			log.Printf("[tools] refresh %s schema failed: %v", t.Name(), err)
		}
	}
	for _, sd := range agent.BuiltinToolSeeds() {
		schema, _ := json.Marshal(sd.Schema)
		if err := s.m.pg.RefreshToolDefaults(sd.Key, sd.Desc, schema); err != nil {
			log.Printf("[tools] refresh %s desc failed: %v", sd.Key, err)
		}
	}
	// Ensure Auto, Solo Pentest, Patch Watch, and Worker have full access to asset, finding, traffic, payload, and patch-monitor tools
	_ = s.m.pg.AddAgentToToolBinding("auto", []string{
		"insert_assets", "list_assets", "add_company_scope", "list_companies",
		"report_finding", "list_findings", "traffic_search", "traffic_get", "traffic_blob",
		"spawn_task", "list_tasks", "pause_task", "get_task_graph", "list_task_findings",
		"add_task_hint", "get_task_worker_trace", "list_task_worker_traces",
		"search_task_worker_traces", "get_task_node_detail",
		"create_skill", "update_skill_file", "create_custom_tool", "update_custom_tool", "create_mcp", "update_mcp",
		"generate_payload", "check_patch_feeds", "generate_vuln_exploit", "search_ios_exploits",
	})
	_ = s.m.pg.AddAgentToToolBinding("pentest", []string{
		"insert_assets", "list_assets", "add_company_scope", "list_companies",
		"report_finding", "list_findings", "traffic_search", "traffic_get", "traffic_blob",
		"create_skill", "update_skill_file",
		"generate_payload", "check_patch_feeds", "generate_vuln_exploit", "search_ios_exploits",
	})
	_ = s.m.pg.AddAgentToToolBinding("patch_watch", []string{
		"insert_assets", "list_assets", "add_company_scope", "list_companies",
		"report_finding", "list_findings",
		"generate_payload", "check_patch_feeds", "generate_vuln_exploit", "search_ios_exploits",
		"create_skill", "update_skill_file",
	})
	_ = s.m.pg.AddAgentToToolBinding("worker", []string{
		"generate_payload", "check_patch_feeds", "generate_vuln_exploit", "search_ios_exploits",
	})
	// Enable web_search and all 20 built-in skills for operational agents
	_, _ = s.m.pg.Exec(`UPDATE agents SET web_search=true WHERE key IN ('auto','pentest','patch_watch','worker','planner','mainagent')`)
	allSkills := []string{
		"api-recon", "auth-and-jwt-attacks", "network-and-service-pentest",
		"osint-and-surface-mapping", "playwright-cli", "scopesentry",
		"waf-and-filter-bypass", "web-vuln-exploitation",
		"anti-forensics", "cc-skimmer", "cookie-exfil",
		"credential-harvesting", "crypto-swap", "data-exfiltration",
		"lateral-movement", "persistence-setup", "post-exploitation-recon",
		"privilege-escalation", "redteam-detection-surface-and-resilience",
		"webshell-deploy",
	}
	for _, agKey := range []string{"auto", "pentest", "patch_watch", "worker"} {
		if a, err := s.m.pg.GetAgentByKey(agKey); err == nil && a != nil {
			for _, sk := range allSkills {
				_, _ = s.m.pg.Exec(`INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled) VALUES($1, $2, true) ON CONFLICT (agent_id, skill_name) DO UPDATE SET enabled=true`, a.ID, sk)
			}
		}
	}
	if autoAgent, err := s.m.pg.GetAgentByKey("auto"); err == nil && autoAgent != nil {
		if tmpl, ok := agent.BuiltinPromptSeeds()["auto"]; ok {
			_, _ = s.m.pg.Exec(`UPDATE agent_prompts SET body=$2 WHERE agent_id=$1 AND version=1`, autoAgent.ID, tmpl)
		}
	}
	// Cap overly large max_tokens (e.g. 16384) to 4096 so 32K context-window models
	// (such as Featherless AI / vLLM) do not reject multi-turn prompts with tool schemas.
	_, _ = s.m.pg.Exec(`UPDATE llm_profiles SET max_tokens=4096 WHERE max_tokens > 4096`)
	// Disable unconfigured HTTP MCP placeholders (e.g. ScopeSentry with empty URL) so they don't log connection errors on every turn
	_, _ = s.m.pg.Exec(`UPDATE mcp_servers SET enabled=false WHERE transport IN ('http','sse') AND COALESCE(TRIM(url),'')=''`)
	_, _ = s.m.pg.Exec(`DELETE FROM agent_visibility WHERE resource_kind='mcp' AND resource_id IN (SELECT id FROM mcp_servers WHERE transport IN ('http','sse') AND COALESCE(TRIM(url),'')='')`)

	// Enable built-in MCP servers that have a valid command or URL (e.g. browser Playwright MCP) for operational agents by default
	if mcpServers, err := s.m.pg.ListMCP(); err == nil {
		for _, srv := range mcpServers {
			hasEndpoint := (srv.Transport == "stdio" && strings.TrimSpace(srv.Command) != "") ||
				(srv.Transport != "stdio" && strings.TrimSpace(srv.URL) != "")
			if hasEndpoint && (srv.Name == "browser" || srv.Enabled) {
				for _, agKey := range []string{"auto", "pentest", "worker", "mainagent", "reporter"} {
					if a, err := s.m.pg.GetAgentByKey(agKey); err == nil && a != nil {
						_, _ = s.m.pg.Exec(`INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled) VALUES($1, 'mcp', $2, '', true) ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO UPDATE SET enabled=true`, a.ID, srv.ID)
					}
				}
			}
		}
	}
	// Enable safe operational platform settings by default without overriding
	// opt-in workflow gates or spawning unsolicited traffic listeners in server.New().
	defaultTrueSettings := []string{
		settingOpsecEnabled,
		settingWebSearchOn,
		settingLLMPoolOn,
		settingLLMPoolBindFallback,
		settingProxyRotateFailure,
		settingNotifyEnabled,
	}
	for _, k := range defaultTrueSettings {
		_ = s.m.pg.SetBool(k, true)
	}
	on, backend, _, _, _ := s.m.WebSearch()
	if !on {
		if backend == "" {
			backend = defaultWebSearchBackend
		}
		_ = s.m.SetWebSearch(true, backend, nil, nil, nil)
	}
	// Refresh built-in and system agent prompts & metadata to English defaults
	for key, tmpl := range agent.BuiltinPromptSeeds() {
		if a, err := s.m.pg.GetAgentByKey(key); err == nil && a != nil {
			_, _ = s.m.pg.ResetPromptToDefault(a.ID, tmpl)
		}
	}
	if a, err := s.m.pg.GetAgentByKey("reporter"); err == nil && a != nil {
		_, _ = s.m.pg.Exec(`UPDATE agents SET name='Report Writer', description='Detailed vulnerability report writer: automatically triggered when a vulnerability is reported, retrieves evidence and execution traces, and writes a Markdown report.' WHERE id=$1`, a.ID)
		_, _ = s.m.pg.ResetPromptToDefault(a.ID, agent.ReporterDefaultPrompt)
	}
	if a, err := s.m.pg.GetAgentByKey(db.FindingRetestAgentKey); err == nil && a != nil {
		_, _ = s.m.pg.Exec(`UPDATE agents SET name='Finding Retester', description='Manually launched from vulnerability details; reads original evidence and saves an independent retest verdict.' WHERE id=$1`, a.ID)
		_, _ = s.m.pg.ResetPromptToDefault(a.ID, agent.RetesterDefaultPrompt)
	}
	if a, err := s.m.pg.GetAgentByKey(db.CredentialAgentKey); err == nil && a != nil {
		_, _ = s.m.pg.Exec(`UPDATE agents SET name='Credential Processor', description='Agent-controlled credential processing: splits usernames, passwords, tokens, and cookies; analyzes only reported content without active login. Can bind its own model; at most one model call per entry.' WHERE id=$1`, a.ID)
		_, _ = s.m.pg.ResetPromptToDefault(a.ID, agent.CredentialProcessorPrompt)
	}
	if triggers, err := s.m.pg.ListTriggersFor("reporter"); err == nil {
		for _, t := range triggers {
			if t.OnToolCall {
				t.ToolCallMessage = reporterToolCallMessage
				_ = s.m.pg.UpdateTrigger(t)
			}
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[tools] refreshed all built-in tools and agent prompts to English defaults")
}

// unbindGoalMetDefault removes goal_met's default "planner" binding ONCE (guarded by
// a settings flag), so existing DBs match the new default of NO agent. goal_met bypasses
// per-goal prove_goal to declare the whole task done — powerful/risky and redundant with
// the prove_goal→auto-complete path — so it ships unbound; users can re-bind it per agent
// in the UI. A user's own binding to another agent is untouched (we only strip planner).
func (s *Server) unbindGoalMetDefault() {
	const flag = "goal_met_unbind_default_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("planner", "goal_met"); err != nil {
		log.Printf("[tools] goal_met 解绑 planner 失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// reseedGoalsPrompt 把 goals 目标拆解器的提示词刷成【当前代码默认】——因为默认正文新增了
// 「先抽操作约束(set_constraints)再拆目标」这一步,而 SeedPromptIfEmpty 首插入only,旧库
// 已有的 version 1 收不到这步。这里用版本管理【追加一个新版本】并切过去(ResetPromptToDefault),
// 旧的版本仍保留在历史里,用户若自定义过可从版本记录找回。settings flag 守卫 → 只做一次;
// 以后默认再变就 bump 这个 flag。全新库无需处理(SeedPromptIfEmpty 已 seed 最新默认)。
func (s *Server) reseedGoalsPrompt() {
	const flag = "goals_prompt_constraint_step_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("goals")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["goals"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] goals 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] goals 提示词已追加新默认版本(加入抽操作约束步,一次性)")
}

// reseedMainAgentPrompt 把 mainagent 提示词刷成【当前代码默认】——默认正文新增了「目标全部
// 达成后 add_intent 直投意图时,反问人是否登记为正式目标」这段引导,而 SeedPromptIfEmpty 首插入
// only,旧库已有版本收不到。用版本管理【追加一个新版本】并切过去(ResetPromptToDefault),旧版本仍
// 保留在历史里,用户若自定义过可从版本记录找回。settings flag 守卫 → 只做一次。全新库无需处理
// (SeedPromptIfEmpty 已 seed 最新默认)。与 reseedGoalsPrompt 完全同构。
func (s *Server) reseedMainAgentPrompt() {
	const flag = "mainagent_prompt_goalless_intent_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("mainagent")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["mainagent"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] mainagent 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] mainagent 提示词已追加新默认版本(加入目标达成后反问建目标,一次性)")
}

// reseedPlannerPrompt 把 planner 提示词刷成【当前代码默认】——默认正文做了精简重构,并把「克制」降级为
// 仅去重、新增「深度优先于覆盖度」「硬底线:目标未达成且无在跑意图必须产出」、给否定结论复核加上界。
// 每次默认有实质变更就 bump 下面的 flag(当前 v2)让存量旧库再刷一次。SeedPromptIfEmpty 首插入only,旧库已有版本收不到,故用版本管理
// 【追加一个新版本】并切过去(ResetPromptToDefault),旧版本仍保留在历史里,用户若自定义过可从版本记录
// 找回。settings flag 守卫 → 只做一次。全新库无需处理(SeedPromptIfEmpty 已 seed 最新默认)。与
// reseedGoalsPrompt 完全同构。
func (s *Server) reseedPlannerPrompt() {
	const flag = "planner_prompt_compact_realistic_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("planner")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["planner"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] planner 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] planner 提示词已追加新默认版本(精简重构+克制降级去重+深度优先+否定复核上界,一次性)")
}

// reseedWorkerPrompt 把 worker 提示词刷成【当前代码默认】——默认正文 record_fact 段删掉了「否定类结论
// 写观察+试探性读法」整句、并把 confidence(observed/inferred)与「是否穷尽本意图手段」解耦(这些易误导规划者),
// 同时把 facts 数组分条收紧为「彼此完全独立、无法归并」的极少数例外。bump flag 至 v3 让存量旧库再刷一次。
// SeedPromptIfEmpty 首插入only,旧库已有版本收不到,故用版本管理【追加一个新版本】并切过去,旧版本仍保留在历史里可找回。
// settings flag 守卫 → 只做一次。全新库无需处理。与 reseedGoalsPrompt 完全同构。
func (s *Server) reseedWorkerPrompt() {
	const flag = "worker_prompt_compact_v4"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次
	a, err := s.m.pg.GetAgentByKey("worker")
	if err != nil || a == nil {
		return // 全新库尚未建 agent 行时,seedPrompts 会直接 seed 最新默认,无需此迁移
	}
	tmpl := agent.BuiltinPromptSeeds()["worker"]
	if tmpl == "" {
		return
	}
	// 全新库 seedPrompts 已 seed 最新默认 → 当前版本已等于代码默认,不必再追加重复版本。
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] worker 提示词重刷为新默认失败: %v", err)
		return
	}
	log.Printf("[prompts] worker 提示词已追加新默认版本(查上下文段收敛为 list_assets/list_findings,去掉 list_facts/node_detail/asset_neighbors,一次性)")
}

const reporterToolCallMessage = "A vulnerability was just registered via report_finding above. Read finding_id (standalone vulnerability record ID) and finding_node_id (exploration node ID) from the returned JSON; " +
	"first call get_finding_traffic(finding_id) to read the current evidence list and its version (an empty list is normal, proceed with writing the report); " +
	"if runtime guidance enables automatic traffic binding, verify and bind traffic for this vulnerability before reading. Use finding_node_id for node details. " +
	"Finally call update_finding_report(finding_id=finding_node_id, report, evidence_version=actual read version) to save; " +
	"evidence_version must be passed, otherwise the report will remain permanently marked as pending update. Do not mix up the two IDs."

// Legacy trigger message (0.3.8 and earlier).
const reporterToolCallMessageV1 = "上面刚有一个漏洞被 report_finding 登记。请从触发上下文里取出 finding_id" +
	"（工具返回 \"finding recorded: <id>\" 里的数字）与任务 id，按你的职责撰写该漏洞的详细报告，" +
	"最后调用 update_finding_report(finding_id, report) 保存。"

func (s *Server) upgradeReporterTriggerMessage() {
	const flag = "reporter_trigger_evidence_version_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()
	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] failed to read triggers: %v", err)
		return
	}
	for _, t := range triggers {
		if !t.OnToolCall || t.ToolCallMessage != reporterToolCallMessageV1 {
			continue
		}
		t.ToolCallMessage = reporterToolCallMessage
		if err := s.m.pg.UpdateTrigger(t); err != nil {
			log.Printf("[reporter] failed to upgrade trigger message: %v", err)
			return
		}
		log.Printf("[reporter] trigger message upgraded to read and pass evidence_version")
	}
}

func (s *Server) seedReporterAgent() {
	const flag = "reporter_agent_seed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()

	if exist, _ := s.m.pg.GetAgentByKey("reporter"); exist != nil {
		return
	}
	a, err := s.m.pg.CreateAgent("reporter", "Report Writer",
		"Detailed vulnerability report writer: automatically triggered when a vulnerability is reported, retrieves evidence and execution traces, and writes a Markdown report.")
	if err != nil {
		log.Printf("[reporter] 创建 agent 失败: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, agent.ReporterDefaultPrompt); err != nil {
		log.Printf("[reporter] seed prompt 失败: %v", err)
	}
	// 触发运行策略：parallel + none —— 一漏洞一报告、多个 finding 并发各写各的。
	// merge 必须为 none：否则(默认 all)一波 finding 会被合并成一次运行，并行就没意义。
	// maxParallel=5：同时最多 5 个报告会话，避免瞬时太多 LLM 调用。
	if err := s.m.pg.SetAgentTriggerBehavior("reporter", "parallel", "none", 5); err != nil {
		log.Printf("[reporter] 设置触发运行策略失败: %v", err)
	}
	// 绑定它需要的工具：写报告 + 读证据/执行过程/态势。
	if err := s.m.pg.AddAgentToToolBinding("reporter", []string{
		"update_finding_report", "get_task_node_detail", "list_task_findings",
		"get_task_worker_trace", "list_task_worker_traces", "search_task_worker_traces",
		"get_task_graph",
	}); err != nil {
		log.Printf("[reporter] 绑定工具失败: %v", err)
	}
	// 触发器：report_finding 被调用即触发（工具返回 "finding recorded: <id>" 带上 finding_id，
	// 任务 id 也在触发消息里）。
	if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
		AgentKey:        "reporter",
		Enabled:         true,
		OnToolCall:      true,
		ToolNames:       []string{"report_finding"},
		ToolCallMessage: reporterToolCallMessage,
	}); err != nil {
		log.Printf("[reporter] 创建触发器失败: %v", err)
	}
	log.Printf("[reporter] 已预置「报告撰写」agent + finding 触发器")
}

// seedAutoReportFindingBinding adds "auto" to report_finding's binding ONCE so
// conversation-context agents can call it without requiring an intent_id.
func (s *Server) seedAutoReportFindingBinding() {
	const flag = "auto_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("auto", []string{"report_finding"}); err != nil {
		log.Printf("[auto] report_finding 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerDefaultBindings adds "planner" to report_finding's binding ONCE
// (guarded by a settings flag), so existing DBs — whose report_finding row was
// seeded as worker-only — also let the planner record findings. Fresh DBs already
// get it via PlannerTools(); this only backfills without overriding a user unbind.
func (s *Server) seedPlannerDefaultBindings() {
	const flag = "planner_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"report_finding"}); err != nil {
		log.Printf("[planner] report_finding 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerListAssetsBinding adds "planner" to list_assets's binding ONCE
// (guarded by a settings flag), so existing DBs — whose list_assets row was seeded
// as auto/pentest-only — also let the planner query the asset store by DSL. Fresh
// DBs already get it via PlannerTools(); this only backfills without overriding a
// user unbind.
func (s *Server) seedPlannerListAssetsBinding() {
	const flag = "planner_list_assets_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"list_assets"}); err != nil {
		log.Printf("[planner] list_assets 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedCompanyScopeRebind changes add_company_scope's default binding ONCE on
// existing DBs (guarded by a settings flag): the tool moves off worker and onto
// planner — defining a company's asset scope is a planning/main/auto concern, not
// something a worker does mid-exploration. Fresh DBs already get planner via
// PlannerTools() and lack worker via WorkerTools(); this only backfills old rows.
// One-shot + flag-guarded so a user who later re-binds worker isn't overridden.
func (s *Server) seedCompanyScopeRebind() {
	const flag = "company_scope_rebind_v1" // worker→planner 默认绑定切换
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"add_company_scope"}); err != nil {
		log.Printf("[planner] add_company_scope 默认绑定失败: %v", err)
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("worker", "add_company_scope"); err != nil {
		log.Printf("[worker] add_company_scope 解绑失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadToolsUnbind strips the read-context tools off worker's default
// binding ONCE on existing DBs (guarded by a settings flag): a worker executes one
// intent and writes back — reading facts/companies and listing all workers' traces is
// a planning/main concern, not the executor's. Fresh DBs already lack these via
// WorkerTools(); this only backfills old rows without overriding a user who
// deliberately re-binds worker. Each RemoveAgentFromTool is per-tool +
// membership-guarded, so planner/mainagent bindings of the same tool are untouched.
//
// NOTE: search_all_worker_traces / get_worker_trace / node_detail are intentionally NOT
// unbound — worker owns them for cross-work look-back + node drill-down (see WorkerTools).
// They used to be in this list back when worker lacked them; seedWorkerReadbackRebind
// repairs DBs whose old run stripped them.
func (s *Server) seedWorkerReadToolsUnbind() {
	const flag = "worker_readtools_unbind_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, k := range []string{
		"list_facts", "list_companies", "list_worker_traces",
	} {
		if err := s.m.pg.RemoveAgentFromTool("worker", k); err != nil {
			log.Printf("[worker] %s 从 worker 解绑失败: %v", k, err)
			return // 出错则不落 flag，下次启动重试
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadbackRebind re-binds the cross-work look-back / drill-down tools onto
// worker ONCE (guarded by a settings flag): an earlier seedWorkerReadToolsUnbind wrongly
// stripped search_all_worker_traces / get_worker_trace / node_detail from worker after
// they had been added to WorkerTools(), so any DB that ran that migration lost them.
// Fresh DBs already have them via WorkerTools() and this is a harmless no-op there.
// One-shot + flag-guarded so a user who later deliberately unbinds them isn't overridden.
func (s *Server) seedWorkerReadbackRebind() {
	const flag = "worker_readback_rebind_v2" // v2: 追加 node_detail
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("worker", []string{
		"search_all_worker_traces", "get_worker_trace", "node_detail",
	}); err != nil {
		log.Printf("[worker] 回看/详情工具补绑失败: %v", err)
		return // 出错则不落 flag，下次启动重试
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedAutoDefaultBindings adds "auto" to the task-op + platform tools' bindings
// ONCE (guarded by a settings flag), so existing DBs whose tool rows were seeded
// before Auto existed still give Auto its default toolset — without re-adding it
// after a user deliberately unbinds.
func (s *Server) seedAutoDefaultBindings() {
	const flag = "auto_default_bindings_v3" // v3: 替换旧资产工具名，加入 insert_assets/add_company_scope
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	keys := make([]string, 0, len(platformToolKeys)+12)
	for _, t := range s.orchestrationTools() {
		keys = append(keys, t.Name())
	}
	keys = append(keys, platformToolKeys...)
	// 资产工具：Auto 操作平台常要看/登记资产、管理公司范围。
	keys = append(keys, "insert_assets", "add_company_scope", "list_assets")
	if err := s.m.pg.AddAgentToToolBinding("auto", keys); err != nil {
		log.Printf("[auto] 默认绑定失败: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedArsenalAndAutoUpgradeV1 binds the Security Arsenal, Browser Inspector,
// Multi-Engine/Exploit Search, and Interception Rule Governance tools to operational
// agents, removes the default 20-minute wall-clock cap on Auto so comprehensive scans
// run to completion, and refreshes Auto's prompt to maximize tool & scanner utilization.
func (s *Server) seedArsenalAndAutoUpgradeV1() {
	const flag = "arsenal_and_auto_upgrade_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	arsenalKeys := []string{
		"list_security_arsenal", "run_security_tool", "browser_inspect",
		"multi_engine_search", "exploit_search",
	}
	for _, agKey := range []string{"auto", "pentest", "worker"} {
		_ = s.m.pg.AddAgentToToolBinding(agKey, arsenalKeys)
	}
	_ = s.m.pg.AddAgentToToolBinding("auto", []string{"list_intercept_rules", "update_intercept_rule"})

	// Lift legacy 1200s (20m) default wall-clock cap on auto so full-site assessments finish cleanly.
	_, _ = s.m.pg.Exec(`UPDATE agents SET run_seconds = 0 WHERE key = 'auto' AND run_seconds = 1200`)

	// Refresh Auto's system prompt to the tool-maximizing v2 prompt.
	if a, err := s.m.pg.GetAgentByKey("auto"); err == nil && a != nil {
		if tmpl := agent.BuiltinPromptSeeds()["auto"]; tmpl != "" {
			if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur != tmpl {
				_, _ = s.m.pg.ResetPromptToDefault(a.ID, tmpl)
			}
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedSelfImprovingScannerToolsV1 binds the new self-improving scanner tools
// (nuclei templates fed by Patch Monitor + automatic XSS execution verification)
// to the offensive agents on databases that were seeded before they existed.
func (s *Server) seedSelfImprovingScannerToolsV1() {
	const flag = "self_improving_scanner_tools_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	newKeys := []string{"sync_nuclei_templates", "verify_xss_execution"}
	for _, t := range append(s.patchMonitorTools(), s.arsenalTools()...) {
		key := t.Name()
		match := false
		for _, k := range newKeys {
			if key == k {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		schema, _ := json.Marshal(t.InputSchema())
		binds, _ := json.Marshal([]string{"auto", "pentest", "worker", "patch_watch", "retester"})
		_ = s.m.pg.SeedTool(key, t.Description(), schema, binds)
		_ = s.m.pg.RefreshToolDefaults(key, t.Description(), schema)
	}
	for _, agKey := range []string{"auto", "pentest", "worker", "patch_watch", "retester"} {
		_ = s.m.pg.AddAgentToToolBinding(agKey, newKeys)
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedLootAndCaptchaToolsV1 seeds save_artifact / list_artifacts (loot vault)
// and solve_captcha into the tools table and binds them to the operational +
// reporting agents (one-shot, settings-flag guarded).
func (s *Server) seedLootAndCaptchaToolsV1() {
	const flag = "loot_and_captcha_tools_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := append(s.artifactTools(), s.captchaTools()...)
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		binds, _ := json.Marshal([]string{"auto", "pentest", "worker", "planner", "mainagent", "reporter", "patch_watch", "retester"})
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), schema, binds)
		_ = s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema)
	}
	keys := make([]string, 0, len(tools))
	for _, t := range tools {
		keys = append(keys, t.Name())
	}
	for _, agKey := range []string{"auto", "pentest", "worker", "planner", "mainagent", "reporter", "patch_watch", "retester"} {
		_ = s.m.pg.AddAgentToToolBinding(agKey, keys)
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedCaptchaAndSearchToolsV2 refreshes solve_captcha (2Captcha v2 Image, Turnstile,
// reCAPTCHA v2/v3, hCaptcha) and multi_engine_search (Brave, Firecrawl, Tavily,
// local SearXNG, Sploitus, DuckDuckGo) schemas and agent bindings on existing DBs.
func (s *Server) seedCaptchaAndSearchToolsV2() {
	const flag = "captcha_and_search_tools_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	refreshTools := append([]actool.CoreTool{}, s.captchaTools()...)
	refreshTools = append(refreshTools, s.toolMultiEngineSearch(), s.toolExploitSearch())
	targetAgents := []string{"auto", "pentest", "worker", "planner", "mainagent", "patch_watch", "retester", "proxy_harvester"}
	binds, _ := json.Marshal(targetAgents)
	keys := make([]string, 0, len(refreshTools))
	for _, t := range refreshTools {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), schema, binds)
		_ = s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema)
		keys = append(keys, t.Name())
	}
	for _, agKey := range targetAgents {
		_ = s.m.pg.AddAgentToToolBinding(agKey, keys)
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedCooldownScheduleToolsV1 seeds schedule_cooldown_resume, list_cooldown_schedules,
// and cancel_cooldown_schedule into the tools catalog and binds them to operational agents.
func (s *Server) seedCooldownScheduleToolsV1() {
	const flag = "cooldown_schedule_tools_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := s.cooldownScheduleTools()
	targetAgents := []string{"auto", "pentest", "worker", "planner", "mainagent", "patch_watch", "retester"}
	binds, _ := json.Marshal(targetAgents)
	keys := make([]string, 0, len(tools))
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), schema, binds)
		_ = s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema)
		keys = append(keys, t.Name())
	}
	for _, agKey := range targetAgents {
		_ = s.m.pg.AddAgentToToolBinding(agKey, keys)
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedBountyHunterToolsV1 seeds the Bug Bounty Finder & Tracker tools and equips
// the built-in `bounty_scout` agent with search, browser, and bounty registration tools.
func (s *Server) seedBountyHunterToolsV1() {
	const flag = "bounty_hunter_tools_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	_, _ = s.m.pg.Exec(`UPDATE agents SET web_search=true WHERE key = 'bounty_scout'`)
	tools := s.bountyHunterAgentTools()
	targetAgents := []string{"bounty_scout", "auto", "pentest", "worker", "planner", "mainagent"}
	binds, _ := json.Marshal(targetAgents)
	keys := make([]string, 0, len(tools))
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), schema, binds)
		_ = s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema)
		keys = append(keys, t.Name())
	}
	for _, agKey := range targetAgents {
		_ = s.m.pg.AddAgentToToolBinding(agKey, keys)
	}
	_ = s.m.pg.AddAgentToToolBinding("bounty_scout", []string{
		"check_proxy_status", "get_proxy_pool_status", "manage_proxy_pool",
		"multi_engine_search", "exploit_search", "browser_inspect",
		"solve_captcha", "report_need",
	})
	if scout, err := s.m.pg.GetAgentByKey("bounty_scout"); err == nil && scout != nil {
		if tmpl := agent.BuiltinPromptSeeds()["bounty_scout"]; tmpl != "" {
			if cur, _ := s.m.pg.CurrentPrompt(scout.ID); strings.TrimSpace(cur) == "" {
				_, _ = s.m.pg.ResetPromptToDefault(scout.ID, tmpl)
			}
		}
		if servers, serr := s.m.pg.ListMCP(); serr == nil {
			for _, srv := range servers {
				if srv.Name == browserMCPName || srv.Name == "recon_osint" {
					_, _ = s.m.pg.Exec(`INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled) VALUES($1, 'mcp', $2, '', true) ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO UPDATE SET enabled=true`, scout.ID, srv.ID)
				}
			}
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedAgentRequestToolsV1 seeds report_need (agent → developer capability
// requests) into the tools table and binds it to every operational + reporting
// agent (one-shot, settings-flag guarded).
func (s *Server) seedAgentRequestToolsV1() {
	const flag = "agent_request_tools_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := s.agentRequestTools()
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		binds, _ := json.Marshal([]string{"auto", "pentest", "worker", "planner", "mainagent", "reporter", "patch_watch", "retester"})
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), schema, binds)
		_ = s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema)
	}
	keys := make([]string, 0, len(tools))
	for _, t := range tools {
		keys = append(keys, t.Name())
	}
	for _, agKey := range []string{"auto", "pentest", "worker", "planner", "mainagent", "reporter", "patch_watch", "retester"} {
		_ = s.m.pg.AddAgentToToolBinding(agKey, keys)
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

func (s *Server) seedProxyPoolAgentToolsV1() {
	const flag = "proxy_pool_agent_tools_v8_scraper_and_harvester"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	_, _ = s.m.pg.Exec(`UPDATE agents SET web_search=true WHERE key IN ('auto','pentest','patch_watch','proxy_harvester','worker','planner','mainagent')`)

	for _, t := range append(append(append(s.proxyPoolAgentTools(), s.patchMonitorTools()...), s.arsenalTools()...), s.toolUpdateFinding(), s.toolUpdateFindingReport()) {
		schema, _ := json.Marshal(t.InputSchema())
		binds, _ := json.Marshal([]string{"auto", "pentest", "worker", "planner", "mainagent", "patch_watch", "proxy_harvester", "retester"})
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), schema, binds)
		_ = s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema)
	}
	proxyFullKeys := []string{
		"check_proxy_status", "import_and_test_proxies", "get_proxy_pool_status", "manage_proxy_pool", "proxied_tcp_relay",
		"scrape_online_proxies", "list_proxy_scrape_sources", "add_proxy_scrape_source", "remove_proxy_scrape_source", "verify_and_import_scraped_proxies",
	}
	arsenalSynergyKeys := []string{
		"search_patch_arsenal", "save_verified_exploit_to_patch_monitor", "update_finding", "update_finding_report",
		"detect_deception_and_honeypot", "create_callback_listener", "poll_callback_events",
		"manage_auth_sessions", "verify_access_control_matrix", "audit_frontend_api_surface",
		"verify_endpoint_idempotency", "audit_source_routes",
	}
	for _, agKey := range []string{"auto", "pentest", "worker", "planner", "mainagent", "patch_watch", "proxy_harvester", "retester"} {
		_ = s.m.pg.AddAgentToToolBinding(agKey, proxyFullKeys)
		_ = s.m.pg.AddAgentToToolBinding(agKey, arsenalSynergyKeys)
	}
	// Equip proxy_harvester with search, skill authoring, and capability-request tools so it can self-improve!
	_ = s.m.pg.AddAgentToToolBinding("proxy_harvester", []string{
		"multi_engine_search", "create_skill", "update_skill_file", "report_need",
	})
	// Read-only / reporting agents also receive check_proxy_status & get_proxy_pool_status so they never guess proxy state.
	for _, agKey := range []string{"reporter", "asset_mapper"} {
		_ = s.m.pg.AddAgentToToolBinding(agKey, []string{"check_proxy_status", "get_proxy_pool_status"})
	}
	patchTargetKeys := []string{
		"search_patch_arsenal", "save_verified_exploit_to_patch_monitor",
		"add_patch_watch_feed", "discover_affected_sites_for_notification",
		"match_vuln_targets", "update_exploit_target_status", "update_finding", "update_finding_report",
		"list_security_arsenal", "run_security_tool", "browser_inspect", "detect_deception_and_honeypot",
	}
	for _, agKey := range []string{"patch_watch", "auto", "pentest", "worker"} {
		_ = s.m.pg.AddAgentToToolBinding(agKey, patchTargetKeys)
	}
	for _, agKey := range []string{"auto", "pentest", "patch_watch", "proxy_harvester", "planner", "worker"} {
		if a, err := s.m.pg.GetAgentByKey(agKey); err == nil && a != nil {
			if tmpl := agent.BuiltinPromptSeeds()[agKey]; tmpl != "" {
				if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur != tmpl {
					_, _ = s.m.pg.ResetPromptToDefault(a.ID, tmpl)
				}
			}
		}
	}
	// Ensure existing DB's Playwright browser MCP has --browser chromium and --ignore-https-errors
	if s.m != nil {
		s.m.syncBrowserMCPProxy()
	}

	// Ensure built-in Playwright browser MCP has root-safe flags, is enabled, and discovers its tools
	if servers, err := s.m.pg.ListMCP(); err == nil {
		for _, srv := range servers {
			if srv.Name == browserMCPName && len(srv.Tools) == 0 {
				srv.Args = encodeJSON(ensureBrowserMCPArgs(decodeStrSlice(srv.Args), true))
				srv.Enabled = true
				if id, serr := s.m.pg.SaveMCP(srv); serr == nil {
					for _, agKey := range []string{"auto", "pentest", "worker", "mainagent", "patch_watch", "reporter"} {
						if ag, aerr := s.m.pg.GetAgentByKey(agKey); aerr == nil && ag != nil {
							_, _ = s.m.pg.Exec(`INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled) VALUES($1, 'mcp', $2, '', true) ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO UPDATE SET enabled=true`, ag.ID, id)
						}
					}
					go s.discoverEmptyMCPsOnStartup()
				}
			}
		}
	}

	_ = s.m.pg.SetSetting(flag, "true")
}

// syncDiscoveredSkillsVisibility ensures every newly shipped or newly created
// skill folder under s.skillDir (e.g. captcha-solving, cloud-and-container-audit,
// deception-and-honeypot-detection, proxy-harvesting) is automatically made
// visible to operational agents once upon first discovery, while preserving any
// later manual toggle-off by the operator.
func (s *Server) syncDiscoveredSkillsVisibility() {
	if s == nil || s.m == nil || s.m.pg == nil || strings.TrimSpace(s.skillDir) == "" {
		return
	}
	entries, err := os.ReadDir(s.skillDir)
	if err != nil {
		return
	}
	const settingKey = "auto_seeded_skill_dirs_v2"
	seeded := map[string]bool{}
	if raw, ok, _ := s.m.pg.GetSetting(settingKey); ok && strings.TrimSpace(raw) != "" {
		var list []string
		if json.Unmarshal([]byte(raw), &list) == nil {
			for _, k := range list {
				seeded[k] = true
			}
		}
	}

	targetAgents := []string{"auto", "pentest", "worker", "planner", "retester", "bounty_scout", "patch_watch", "mainagent"}
	var agentIDs []int64
	for _, ak := range targetAgents {
		if a, aerr := s.m.pg.GetAgentByKey(ak); aerr == nil && a != nil {
			agentIDs = append(agentIDs, a.ID)
		}
	}

	changed := false
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if name == "scopesentry" || seeded[name] {
			continue
		}
		if _, stErr := os.Stat(filepath.Join(s.skillDir, name, "SKILL.md")); stErr != nil {
			continue
		}
		for _, aid := range agentIDs {
			_, _ = s.m.pg.Exec(`INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled) VALUES($1, $2, true) ON CONFLICT (agent_id, skill_name) DO UPDATE SET enabled=true`, aid, name)
		}
		if name == "proxy-harvesting" || name == "osint-and-surface-mapping" {
			if ph, perr := s.m.pg.GetAgentByKey("proxy_harvester"); perr == nil && ph != nil {
				_, _ = s.m.pg.Exec(`INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled) VALUES($1, $2, true) ON CONFLICT (agent_id, skill_name) DO UPDATE SET enabled=true`, ph.ID, name)
			}
		}
		seeded[name] = true
		changed = true
	}

	if changed {
		out := make([]string, 0, len(seeded))
		for k := range seeded {
			out = append(out, k)
		}
		if b, merr := json.Marshal(out); merr == nil {
			_ = s.m.pg.SetSetting(settingKey, string(b))
		}
	}
	s.reconcileExistingSkillMisses()
}

// seedAutoTaskDelegationV2 upgrades the default Auto Super-Agent prompt in
// existing PostgreSQL databases so engagement/scan requests in /chat are
// automatically converted into pre-filled parallel Multi-Agent Tasks with
// live Task -> Chat callback updates instead of burning tokens solo in Chat.
func (s *Server) seedAutoTaskDelegationV2() {
	const flag = "auto_task_delegation_prompt_v3"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if a, err := s.m.pg.GetAgentByKey("auto"); err == nil && a != nil {
		if tmpl := agent.BuiltinPromptSeeds()["auto"]; tmpl != "" {
			if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur != tmpl {
				_, _ = s.m.pg.ResetPromptToDefault(a.ID, tmpl)
			}
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
