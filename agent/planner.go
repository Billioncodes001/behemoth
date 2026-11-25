package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/behemoth/db"
	"github.com/Autumn-27/behemoth/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	findingRecorder   FindingRecorder
	prov              llm.Provider
	model             string
	tx                *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window            int                                    // context window in tokens (for compaction)
	windowFn          func() int                             // optional dynamic task-chain minimum
	maxTurns          int                                    // max agent turns per run (0 = unlimited)
	killWork          func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork         func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr         string                                 // recording proxy for WebFetch (empty = direct)
	proxyAddrFn       func() string
	webFetchProxyFn   func() string
	proxyCACert       string        // recording proxy's CA cert path (HTTPS verify)
	webSearch         WebSearchOpts // web_search tool backend selection (off by default)
	workDir           string        // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints func() bool   // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn    func() bool   // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn      func() bool   // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn       func() int    // resolver: per-reply output cap (nil/0 = send no cap)
	compactor         *Compactor    // cold-node compaction (§7); nil = disabled

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string)              { p.proxyAddr, p.proxyCACert = addr, caCert }
func (p *Planner) SetProxyProvider(fn func() string)         { p.proxyAddrFn = fn }
func (p *Planner) SetWebFetchProxyProvider(fn func() string) { p.webFetchProxyFn = fn }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your Persistent Planning Todos (carried across wake-ups from your previous round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed accordingly: dispatch intents ONLY for next steps whose prerequisite steps are completed or whose dependent facts already exist; update the list with TodoWrite (mark steps satisfied by facts as completed). Do not re-dispatch steps already marked pending/in_progress.")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" — a worker reported a finding on intent IntentID (Detail = 摘要).
//	"goal"    — the human (via 主 agent 的 set_goals) added one OR MORE goals in a
//	            single call (Goals = 本次新增的目标文本，1+ 条；set_goals 支持批量).
//	"goal_deleted" — the human deleted a goal from 总览的目标管理 (Detail = 被删目标文本).
//	"goal_edited"  — the human edited a goal from 总览的目标管理 (OldGoal→NewGoal 文本).
//	"cancelled" — the human deleted intent IntentID (Detail = 删除原因). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // Kind=="cancelled" 专用：删除前捕获的意图摘要（真删除后节点已不存在，无法再查）
	Goals    []string // Kind=="goal" 专用：本次 set_goals 新增的目标文本（1 条或多条）
	OldGoal  string   // Kind=="goal_edited" 专用：修改前的目标文本
	NewGoal  string   // Kind=="goal_edited" 专用：修改后的目标文本
	Hints    []string // Kind=="hint" 专用：本次 add_hint 新增的提示文本（1 条或多条）
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Actual Changes Triggering This Round (Review these first before deciding whether to add new directions)]:")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- Human (main agent) added a new goal: %s — new objective to achieve; add exploration directions accordingly (if not already covered).", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- Human (main agent) added %d new goals: %s — all are new objectives to achieve; add exploration directions for any uncovered goals.", len(ev.Goals), strings.Join(ev.Goals, "; ")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- Human (main agent) added a strategic hint: %s — attached to the exploration graph; adjust or add exploration directions accordingly.", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- Human (main agent) added %d strategic hints: %s — attached to the exploration graph; adjust or add exploration directions accordingly.", len(ev.Hints), strings.Join(ev.Hints, "; ")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- Human deleted goal: %s — this goal has been removed; re-evaluate remaining goals/directions (no need to dispatch further intents for it).", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- Human modified goal from \"%s\" to \"%s\" — adjust exploration directions for the new goal (stop dispatching for the old one if no longer applicable).", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- Worker for intent #%d (%s) reported a finding: %s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "cancelled":
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- Intent #%d was deleted by user; intent content: %s, deletion reason: %s. This intent is deleted (will not execute); re-plan accordingly.", ev.IntentID, sm, ev.Detail))
		default: // "done"
			b.WriteString(fmt.Sprintf("\n- Worker for intent #%d (%s) finished; output conclusion: %s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("; new fact IDs yielded by this intent: %s ", fids))
			}
		}
	}
	b.WriteString("\n(Query full details on demand via node_detail / get_worker_output / list_findings.)")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12、#15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, "、")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(failed to fetch output)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(no output recorded for this work)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " … (truncated, see get_worker_output for full text)"
}

func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[Current Situational Overview (pre-fetched graph_overview, identical to calling the tool; call node_detail/list_facts etc. on demand for deeper details)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间产物输出规约
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "Planner" of an authorized penetration testing system, woken whenever the exploration or asset graph changes. Your role: Read Situational Overview -> Judge Goals -> **Add new exploration intents ONLY when genuinely uncovered directions exist**. You are a planner, NOT an executor: your output this round must be [generating/clarifying intents] or [judging goals] — never perform the full exploitation work yourself inside the planning loop.

Task Goal: {{.Goal}}

**How Many Intents to Produce This Round (Consider This First)**:
- **Hard Floor (Highest Priority)**: Whenever [goals are not yet met] AND [there are currently NO open or running intents] (frontier_open=0 and running_intents is empty), you MUST produce at least one intent advancing toward the goal this round — with no running work to wait for and nothing queued, producing 0 intents stalls the task.
- Outside the hard floor, **producing 0 intents is a normal outcome when justified**: (1) **Already Covered** — the directions you have in mind are already being handled by open/running intents (duplicating existing intents with rephrased wording is a serious error); (2) **Waiting on Dependencies** — the next step depends on the output of a currently running work that hasn't finished yet.
- Conversely, when genuinely [uncovered directions that do not depend on in-flight work] exist and the goal is not yet met, dispatch them proactively.

**Decision Workflow on Every Wake-up**:

1. **The Full Situational Overview Is Attached Below** (identical to graph_overview output; no need to call graph_overview again): task (description + goal), asset counts, goals + states, open/running/recent_done intents, sites_without_endpoints, facts count, and recent_facts ({id,summary,confidence?}).
   - **Scope**: Exploration nodes (goals/intents/facts/findings) belong to this task; **assets are isolated per task by default** (this task and explicitly linked tasks; global assets are visible only if 'Share Global Assets' is enabled). Ignore unrelated assets.
   - **Lineage**: Each intent carries parents (upstream facts/intents it derived from) and yields (downstream facts/findings it produced), and each item in recent_facts carries from_intent.
   - **Negative / Tentative Observations** (e.g., "port closed / not injectable" in recent_facts) are worker observations, not final verdicts: inspect evidence via node_detail(id) before accepting them — treat a direction as temporarily closed only if evidence is solid, confidence=observed, and techniques were exhausted; if evidence is weak, only probed once, or confidence=inferred, treat it as [unverified] and dispatch at most one verification intent if within scope and uncovered.
   - **Call On-Demand Tools Only for Deeper Details**: list_facts (paginated, newest first), list_findings (all vulnerabilities), node_detail(id) (full evidence/detail), list_assets (DSL search, type/company_id filter, or id/ids fetch).

2. **Judge Goals (Core Responsibility)**: The goals field lists all goals and their states; for any open goal proven by a finding or fact, call prove_goal(goal_id, evidence_id, reason) to mark it met. **When you mark the last remaining open goal as met, the system automatically concludes the entire task**.
   - ⚠️ **Quantitative Acceptance Check (Never Mark Met Prematurely)**: When a goal includes quantitative criteria (e.g., coverage >= X%, N findings, specific privilege level), you MUST verify the actual measured values in graph_overview (coverage.pct, findings_total, etc.) before calling prove_goal.

3. **(Optional, Opening Round Only, Ultra-Lightweight) Initial Recon**: Only when the graph has almost no facts yet (recent_facts is empty at task start) and the overview alone isn't enough to formulate concrete initial intents, you may run at most 1–3 lightweight read-only probes (e.g., curl homepage/headers) solely to write a more specific intent description. Once facts > 0, never probe yourself — dispatch intents to workers.

4. **Decide Which New Directions to Add**: Compare candidate directions against open + running + recent_done intents:
   - Already covered by open/running -> do not duplicate.
   - Present in recent_done -> check the intent's state:
     · **done**: covered; do not re-dispatch unless materially new mechanics (new fact/asset/parameter/distinct technique) emerge, and clearly state how it differs in summary.
     · **exhausted (budget hit mid-run) / blocked (model or network error)**: inspect progress via get_worker_trace / get_worker_output; if close to a breakthrough, dispatch a continuation intent; if blocked by transient error, re-dispatch; if repeatedly stuck at the same spot, pivot technique.
   - **Depth Over Breadth & Mandatory Post-Finding Exploitation**: Coverage is a floor, not the primary objective. **Surface findings are starting points, NOT stopping points**: whenever a worker records a Low/Medium/High finding (e.g. outdated client-side libraries with known XSS CVEs, reflected inputs, exposed APIs, weak auth/CORS, version disclosures) whose full weaponized exploitation or chaining has not yet been attempted, **proactively dispatch follow-up exploitation intents (` + "`parent_ids=[finding_node_id]`" + `)** instructing workers to check ` + "`search_patch_arsenal`" + `, build/execute live PoCs to prove maximum impact, escalate severity via ` + "`update_finding`" + `, and persist verified PoCs via ` + "`save_verified_exploit_to_patch_monitor`" + `!
   - **Maintain Route Diversity**: Keep 2–3 mechanistically distinct routes advancing in parallel while respecting all top-level [Operational Constraints].
   - **Serial Exploit Chains — Dispatch Step by Step**: For strict serial chains (1 -> 2 -> 3 where step 2 requires step 1's actual output), record the chain in TodoWrite and dispatch only the step whose prerequisites are met this round.

5. **Submit**: Call add_intent **once** in batch mode (intents array, up to 4 highest-value directions):
   - **summary**: One-sentence natural language description (full target address + what to do + why).
   - **asset_ids**: Target asset IDs (from list_assets) whenever the direction targets specific assets.
   - **parent_ids**: Upstream fact/finding node IDs that this direction derives from (leave empty for top-level initial directions).

Be concise, focused, and effective.`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir) + needReportNote
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	// 资产覆盖度功能关闭时剔除 add_task_scope/list_untested_assets（不入 prompt）。
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// 关键态势（刚完成的意图 + 预取的完整图）改放【本轮 user 输入】(见下方 input)，system
	// 只留静态规划正文。move-out 让 system 每轮稳定、更利于缓存；代价是若单轮变长，态势可能
	// 被 compaction 压缩（planner 单轮通常短，风险低）。situational 会拼进下方 input。
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())
	// 任务级 deadline / 终局模式(经 ctx 注入,见 taskclock.go)。终局那一轮把任务超时
	// planner 收尾词作为【本轮操作指令】拼进本轮 user 输入(随 situational),让它只做最后
	// 目标判定、不产新意图。
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task Final Wrap-Up (Special instruction for this round, overriding the normal planning workflow above)]: " + resolveTaskTimeoutWrapup("planner")
	}
	// 本任务的工作目录 <workDir>/tasks/<taskID>，先建好。
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	resolvePlannerProxy := func() string {
		if p.proxyAddrFn != nil {
			return p.proxyAddrFn()
		}
		return p.proxyAddr
	}
	resolvePlannerHTTPProxy := func() string {
		if px := resolvePlannerProxy(); px != "" {
			return px
		}
		if p.webFetchProxyFn != nil {
			return p.webFetchProxyFn()
		}
		return ""
	}
	// Planner-side scope enforcement: same mechanical allowlist the workers use, so
	// a planning-round probe (curl/nmap) cannot wander outside task_scope either.
	scopeGuard := NewTaskScopeGuard(as, taskID)
	tools = append(tools, ScopedHTTPToolWithProxy(scopeGuard, resolvePlannerHTTPProxy, p.proxyCACert))
	tools = wrapScopeGuardTools(tools, scopeGuard)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // 操作约束(若有)注入系统提示,框定探索边界
	}
	sysBody += scopeHintForPrompt(scopeGuard)
	system, boundary := deferredSystem(sysBody, def)
	// planner 无自身墙钟预算;有 deadline 时把 MaxDuration 夹逼到剩余,让在跑的规划轮在
	// 任务到点时进收尾(因超时→任务超时词,因步数→per-run 词)。
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	proxyAddr := resolvePlannerProxy()
	webFetchProxy := proxyAddr
	if webFetchProxy == "" && p.webFetchProxyFn != nil {
		webFetchProxy = p.webFetchProxyFn()
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           wrapDynamicProxyEnvTools(append(tools, deepSeekTools(p.webSearch)...), resolvePlannerProxy, p.proxyCACert),
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   webFetchProxy,
		WebFetchCACert:  p.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:    p.webSearch.Enabled && p.webSearch.Backend != "deepseek",
		WebSearchBackend:   p.webSearch.Backend,
		BraveSearchAPIKey:  p.webSearch.BraveKey,
		TavilySearchAPIKey: p.webSearch.TavilyKey,
		WebSearchProxy:     p.webSearch.Proxy,
		BashEnv:            agentBashEnv(proxyAddr, p.proxyCACert), // Bash 子命令默认走代理+信任 CA
		WorkingDir:         taskDir,                                // 本任务工作目录 <workDir>/tasks/<taskID>
		ToolOutputDir:      cmdOutDir(taskDir),
		MaxTurns:           p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:        maxDur,     // 0=不限;有 deadline 时=距 deadline 剩余
		Compaction:         compactionConfig(p.compactionWindow()),
		// 跨唤醒共享的规划待办：让串行链在多轮之间保留（session 是新的，store 不是）。
		Todos: p.todoFor(ts.ID()),
		// 命中【本轮】步数预算→ SDK 跑收尾:把本轮已想清楚的结论落地(该派的 add_intent、
		// 能证的 prove_goal、串行链记 TodoWrite),而非停止规划——planner 之后仍会被反复唤醒。
		// clamped(被任务 deadline 夹逼)时改用 PromptByReason(见 wrapupSettlementForTask)。
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    p.maxTokens(),    // 0 = 不发上限,由服务端默认值决定
	}
	// Wire planner continuation hooks so if the planner outputs a status sentence
	// or fails a tool call without calling add_intent / prove_goal when intents are needed,
	// it is automatically nudged to complete its planning round.
	opts.Hooks = WrapPlannerContinuationHooks(opts.Hooks, fmt.Sprintf("planner-%d", taskID), 4)
	// Extra run budgets (tokens / tool calls). Unconfigured agents get no wrappers.
	applyRunBudget(&opts, "planner")
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	// 态势（刚完成的意图 + 完整图）现在拼进本轮 user 输入（见下方 input）。user 里还有
	// 指令 + 跨唤醒待办（todo 是模型自己的规划便签，可再生，放 user 即可）。
	// 开场白按「本轮有无具体变动」分两种：有变动 → 指向下方【实际变动】块；无变动
	// (心跳定时巡检 / hint / 恢复等) → 别谎称"图发生了变化",转而提示顺带复查在跑意图。
	lead := "Concrete changes just occurred (see [Actual Changes Triggering This Round] below); plan the next steps accordingly:"
	if len(triggers) == 0 {
		lead = "This round is a **periodic heartbeat check / wake-up without a specific change signal** — the graph may not have new changes. Review running intents along the way: use steer_work to course-correct stalled or off-track workers and kill_work to stop completely misguided ones; then evaluate goals and decide whether to add new directions:"
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "This round is a **periodic heartbeat check**, and there are currently **NO open or running intents** — no workers are running and no directions are queued, so exploration is stalled. You **MUST** produce one or more non-duplicate intents advancing toward the goal in this round (do NOT produce 0 intents); first check whether the goal is already met based on the overview below, and if not, immediately add new directions:"
		}
	}
	input := lead + situational + "\n\nBased on the situational overview above, evaluate the goals. When a goal is [genuinely achieved] (target objective obtained / target vulnerability confirmed), mark each met goal using prove_goal. **Hard Floor: As long as goals are not yet met AND there are currently NO open or running intents (frontier_open=0 and running_intents is empty), you MUST produce at least one intent advancing toward the goal in this round — with no running work to wait for and nothing queued, producing 0 intents stalls the task. You may produce 0 new intents ONLY when open/running intents are already progressing or all goals are met.**" +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration 现在会在墙钟到点打断在跑工具并就地进收尾(在活 ctx 上),单轮卡死不再
	// 绕过收尾,无需外部硬 ctx 兜底。ctx 只承载 pause / kill / shutdown。
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
