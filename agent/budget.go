package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"sync"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// Run budgets: turns (MaxTurns) and wall-clock (MaxDuration) already bound a run
// inside the harness. Two dimensions were missing and are what actually blow up
// an autonomous engagement's cost:
//
//   - tokens: a loop that keeps calling cheap, fast tools can burn millions of
//     tokens while staying under both the turn and the time budget;
//   - tool calls: a cheap-model loop can fire hundreds of probes per turn.
//
// This file adds both as hard, per-run budgets. Tokens are counted by wrapping
// the provider (every Stream/Complete usage is folded in exactly like the
// harness accumulator does); tool calls are counted by wrapping each tool's
// Call. Once a dimension is exhausted, further tool calls return an error result
// telling the model to stop probing and wrap up — the run then ends naturally on
// its next text-only turn.
//
// A refusal never blocks the write-back tools in budgetWriteBackTools, so a
// budget-exhausted run can still persist findings/assets before finishing.

// BudgetLimits is a run's extra budget dimensions. Both zero = disabled.
type BudgetLimits struct {
	MaxTokens    int `json:"max_tokens,omitempty"`
	MaxToolCalls int `json:"max_tool_calls,omitempty"`
}

// Enabled reports whether at least one dimension is active.
func (l BudgetLimits) Enabled() bool { return l.MaxTokens > 0 || l.MaxToolCalls > 0 }

// BudgetOverride, if set, returns the admin-configured budget for an agent key
// and whether one exists. Wired by the server to the agents table
// (agents.token_budget / agents.tool_call_budget), like WrapupOverride. nil or
// all-zero → both dimensions off (prior behavior).
var BudgetOverride func(agentKey string) (BudgetLimits, bool)

// resolveBudgetLimits returns the effective limits: the DB-configured values, or
// zero (both dimensions off) when nothing is configured.
func resolveBudgetLimits(agentKey string) BudgetLimits {
	if BudgetOverride != nil {
		if l, ok := BudgetOverride(agentKey); ok {
			return l
		}
	}
	return BudgetLimits{}
}

// budgetWriteBackTools are always allowed through the tool-budget gate: the point
// of the budget is to stop *probing*, not to prevent the run from persisting what
// it already learned.
var budgetWriteBackTools = map[string]bool{
	"insert_assets":                          true,
	"record_fact":                            true,
	"report_finding":                         true,
	"update_finding":                         true,
	"bind_finding_traffic":                   true,
	"save_verified_exploit_to_patch_monitor": true,
	"save_artifact":                          true,
	"report_need":                            true,
	"mark_done":                              true,
	"prove_goal":                             true,
	"add_intent":                             true,
	"set_goals":                              true,
	"set_constraints":                        true,
	"TodoWrite":                              true,
	"Skill":                                  true,
}

// RunBudget tracks one run's token and tool-call spend against its limits.
type RunBudget struct {
	mu     sync.Mutex
	limits BudgetLimits
	tokens int
	calls  int
	// reason is the first-exhausted dimension's message; empty until a limit is
	// hit. Kept so every refused call explains the same cause.
	reason string
}

// NewRunBudget builds a budget for agentKey. Returns nil when both dimensions
// are off so callers can skip the wrappers entirely.
func NewRunBudget(agentKey string) *RunBudget {
	return NewRunBudgetLimits(resolveBudgetLimits(agentKey))
}

// NewRunBudgetLimits builds a budget from explicit limits (tests, embedders).
func NewRunBudgetLimits(limits BudgetLimits) *RunBudget {
	if !limits.Enabled() {
		return nil
	}
	return &RunBudget{limits: limits}
}

// AddUsage folds one model call's token usage into the budget. Prompt and
// completion tokens both count — the spend and the context pressure are real.
func (b *RunBudget) AddUsage(u llm.Usage) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens += u.InputTokens + u.OutputTokens + u.CacheReadTokens + u.CacheWriteTokens
	b.evalLocked()
}

// evalLocked (re)computes the exhausted reason from the current counters.
// Callers hold b.mu.
func (b *RunBudget) evalLocked() {
	if b.reason != "" {
		return
	}
	if b.limits.MaxTokens > 0 && b.tokens >= b.limits.MaxTokens {
		b.reason = fmt.Sprintf("token budget exhausted (%d/%d tokens)", b.tokens, b.limits.MaxTokens)
		return
	}
	if b.limits.MaxToolCalls > 0 && b.calls >= b.limits.MaxToolCalls {
		b.reason = fmt.Sprintf("tool-call budget exhausted (%d/%d calls)", b.calls, b.limits.MaxToolCalls)
	}
}

// TakeToolCall records one tool call and reports whether it may execute. The
// second return is the guidance handed back to the model when denied. Write-back
// tools bypass the limit entirely.
func (b *RunBudget) TakeToolCall(name string) (bool, string) {
	if b == nil {
		return true, ""
	}
	b.mu.Lock()
	// Check before spending: a call is allowed while calls < MaxToolCalls, so exactly
	// MaxToolCalls calls execute. A token budget exhausted by AddUsage refuses here.
	reason := b.reason
	if reason == "" && b.limits.MaxToolCalls > 0 && b.calls >= b.limits.MaxToolCalls {
		b.reason = fmt.Sprintf("tool-call budget exhausted (%d/%d calls)", b.calls, b.limits.MaxToolCalls)
		reason = b.reason
	}
	if reason == "" {
		b.calls++
	}
	b.mu.Unlock()
	if reason == "" || budgetWriteBackTools[name] {
		return true, ""
	}
	return false, fmt.Sprintf("Run budget exhausted: %s. Do not call more probing tools — write back what you already found (record_fact / insert_assets / report_finding) and finish with a single plain-text sentence.", reason)
}

// Snapshot returns the current counters and the exhausted reason ("" while the
// run is still within budget).
func (b *RunBudget) Snapshot() (tokens, calls int, reason string) {
	if b == nil {
		return 0, 0, ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens, b.calls, b.reason
}

// Limits returns the configured limits.
func (b *RunBudget) Limits() BudgetLimits {
	if b == nil {
		return BudgetLimits{}
	}
	return b.limits
}

// Summary is the budget record handed to the activity stream at run end.
func (b *RunBudget) Summary() map[string]any {
	if b == nil {
		return nil
	}
	tokens, calls, reason := b.Snapshot()
	return map[string]any{
		"max_tokens":     b.limits.MaxTokens,
		"max_tool_calls": b.limits.MaxToolCalls,
		"tokens":         tokens,
		"tool_calls":     calls,
		"exhausted":      reason,
	}
}

// ---------- provider wrapper ----------

// budgetProvider counts every model call's usage into a RunBudget while passing
// events through untouched. Counting mirrors the harness accumulator: usage is
// accumulated from message_start AND message_delta events (the two places
// providers report it), so the budget sees the same numbers the trace does.
type budgetProvider struct {
	llm.Provider
	budget *RunBudget
}

// WrapProvider returns p wrapped to count usage into b. Returns p unchanged when
// b is nil.
func (b *RunBudget) WrapProvider(p llm.Provider) llm.Provider {
	if b == nil || p == nil {
		return p
	}
	return &budgetProvider{Provider: p, budget: b}
}

func (p *budgetProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		for ev, err := range p.Provider.Stream(ctx, req) {
			if err == nil && (ev.Type == llm.SEMessageStart || ev.Type == llm.SEMessageDelta) {
				p.budget.AddUsage(ev.Usage)
			}
			if !yield(ev, err) {
				return
			}
		}
	}
}

func (p *budgetProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	msg, stop, usage, err := p.Provider.Complete(ctx, req)
	if err == nil {
		p.budget.AddUsage(usage)
	}
	return msg, stop, usage, err
}

// ---------- tool wrapper ----------

// budgetedTool counts a tool call and refuses execution once the budget is spent.
type budgetedTool struct {
	actool.CoreTool
	budget *RunBudget
}

func (t *budgetedTool) AcceptsRawInput() bool {
	if ra, ok := t.CoreTool.(rawInputAcceptor); ok {
		return ra.AcceptsRawInput()
	}
	return false
}

func (t *budgetedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	ok, msg := t.budget.TakeToolCall(t.Name())
	if !ok {
		return actool.Errorf(msg), nil
	}
	return t.CoreTool.Call(ctx, in, tc)
}

// wrapBudgetTools wraps every tool so its calls count against the run budget.
// Returns tools unchanged when b is nil.
func wrapBudgetTools(tools []actool.CoreTool, b *RunBudget) []actool.CoreTool {
	if b == nil || len(tools) == 0 {
		return tools
	}
	out := make([]actool.CoreTool, len(tools))
	for i, t := range tools {
		out[i] = &budgetedTool{CoreTool: t, budget: b}
	}
	return out
}

// applyRunBudget installs the per-agent run budget on agentcore options: the
// provider counts tokens, the tools count calls. Safe to call for any agent key
// (unconfigured agents get no wrappers and no behavior change).
func applyRunBudget(opts *agentcore.Options, agentKey string) *RunBudget {
	b := NewRunBudget(agentKey)
	if b == nil {
		return nil
	}
	opts.Provider = b.WrapProvider(opts.Provider)
	opts.Tools = wrapBudgetTools(opts.Tools, b)
	return b
}
