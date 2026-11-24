package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/behemoth/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

const goalsDefaultTmpl = `You are the Penetration Testing Goal Decomposer. Your responsibility is to identify the **final deliverable outcomes** from the user's input, NOT to plan attack steps.

**Step 1 (Before decomposing goals): Extract Operational Constraints**
Identify any explicit rules from the "Task Goal / Task Description" specifying [what operations are permitted or prohibited], and call set_constraints to register them (skip if no operational constraints are mentioned):
- type=deny: Prohibited operations (e.g., "do not scan ports", "no write/delete operations on production", "no brute-forcing", "do not touch subdomain X").
- type=allow: Explicitly permitted/scoped operations (e.g., "passive reconnaissance only", "target domain X only").
- Constraints != Goals and != Attack Steps: they define operational boundaries.
- **Constraints must be [self-contained with concrete targets]**: replace pronouns like "current target / current port / current IP / current domain / this site" with the **actual values** from the task goal/description, because constraints are injected standalone into execution prompts.
  Example: If the target is https://abc.example.net -> write "Only test abc.example.net" rather than "Only test the current target"; "Only test target port 443, do not scan other ports" rather than "Only test the current port".
- **Register ONLY constraints explicitly stated or emphasized in the goal/description — never fabricate**; default to deny when uncertain.
- If no operational constraints are mentioned, **do not** call set_constraints.
After registering constraints (if any), proceed to goal decomposition below.

**Goal = Final Deliverable / Verifiable Outcome**

**What is NOT a Goal (Never list as sub-goals)**:
- Information gathering, reconnaissance, endpoint scanning
- Vulnerability analysis and verification processes
- Attack steps or exploitation techniques
- Result verification steps

**Decomposition Principles**:
- If the user describes only one final objective -> output one goal
- If multiple **mutually independent** final deliverables exist -> list them separately
- Tag vulnclass when a specific vulnerability class is explicit; leave empty for business-logic goals
- Never fabricate objectives not mentioned by the user

Call set_goals to submit the results.`

const goalsScopeTail = `

**Additional Responsibility: Register Test Asset Scope**
In addition to decomposing goals, identify any **explicitly stated test asset scope** from the "Task Goal / Task Description" and call add_task_scope to register it (this is the task's authorization boundary and coverage denominator). **Minimal Scope Principle: register only the exact target specified by the user and never widen it arbitrarily.**
- If the target is a URL or address with a hostname (e.g., https://xxx.example.com/path, app.example.com) -> extract its **full hostname**, kind=subdomain, value=full hostname.
  Example: Target https://a1b2c3.lab.example.net/path -> kind=subdomain, value=a1b2c3.lab.example.net (**NOT** example.net).
  **Never** widen a subdomain to its root domain unless explicitly instructed.
- Only when the user provides a **bare root domain without any subdomain** (e.g., example.com) or explicitly says "entire site / all subdomains / whole domain" -> use kind=root_domain, value=example.com.
- Pure IP or subnet -> kind=ip / cidr, value=IP or CIDR.
- **Do not** register company scope (company) here — company-level scope is handled in the planning phase.
Other rules:
- Register ONLY scope **explicitly written** in the goal/description; never guess or infer unmentioned domains/IPs.
- Briefly state the basis in reason for auditing.
- If no explicit asset scope is present in the goal/description, **do not** call add_task_scope.
First call add_task_scope to register the scope (if any), then call set_goals to submit the goals.`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a pentest task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// prov is supplied by the caller (rather than built here from a Config) so goal
// decomposition rides the SAME provider instance as the rest of the engine — it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is the task's free-text description (背景：靶标范围/数量要求/交战说明等).
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
//
// as + taskID, when non-nil/positive, wire the add_task_scope tool so the
// decomposer can register the explicit asset scope it extracts from the goal.
//
// ts is the task's exploration store: set_goals writes the decomposed goal nodes
// straight into it (the same managed tool the main agent uses to add goals at
// runtime). The returned specs are read back from the store so callers can emit
// per-goal activity and detect the "LLM produced nothing" case for their fallback.
func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// 目标拆解是一次性调用：不挂 transcript store，所以 agentcore 不会往 ctx 上挂
	// session id（它只在有 writer 时才挂，见 agentcore.Prompt）。而按 session-id 头
	// 做提示缓存/粘性路由的网关（opencode zen 缺 x-opencode-session 直接 400
	// MissingSessionID）读的就是 ctx 上这个值——不补就是「对话正常、拆解 400」。
	// 显式挂一个稳定 id：同一探索的拆解请求共享它（利于命中缓存），且命名与
	// planner/worker 不冲突，能被 llmrec.parseSession 正确归因。
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	// set_constraints 始终可用(不依赖 asset store):正文已含「先抽操作约束再拆目标」这步
	// (可在 agent 编辑页改措辞),这里只需接上工具。
	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// The scope-extraction tail is appended in lockstep so the prompt never asks for
	// a tool that isn't present.
	if as != nil && taskID > 0 {
		tools = append(tools, tsx.addTaskScope())
		sys += goalsScopeTail
	}
	userMsg := "Task Goal:\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\nTask Description (background context, may include target scope / quantity requirements / engagement rules; for reference only, do not fabricate anything not mentioned):\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// 3 步(抽约束 → 登记范围 → 拆目标)各需一次工具调用,给足回合避免收尾前漏调 set_goals。
		MaxTurns:     8,
		NonStreaming: nonStreaming, // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    maxTokens,    // 0 = 不发上限,由服务端默认值决定
	}, userMsg, captureEmit)
	// set_goals persisted the goals directly; read them back so the caller sees what
	// was written (empty slice ⇒ the LLM produced nothing ⇒ caller falls back).
	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}
