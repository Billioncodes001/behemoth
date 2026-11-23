package agent

import (
	"context"
	"encoding/json"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// usageProvider is a provider stub that reports fixed usage and answers with text.
type usageProvider struct {
	in, out int
	text    string
}

func (p usageProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: p.in}}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: p.text}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn", Usage: llm.Usage{OutputTokens: p.out}}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (p usageProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.text)}},
		"end_turn", llm.Usage{InputTokens: p.in, OutputTokens: p.out}, nil
}

// countingTool is a CoreTool that records how many times it actually ran.
func countingTool(name string, ran *int) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: name,
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			*ran++
			return actool.Text("ok"), nil
		},
	})
}

func drainUsage(t *testing.T, p llm.Provider) {
	t.Helper()
	for _, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
	}
}

// The provider wrapper must fold prompt + completion tokens into the budget.
func TestBudgetCountsProviderTokens(t *testing.T) {
	b := NewRunBudgetLimits(BudgetLimits{MaxTokens: 1000})
	if b == nil {
		t.Fatal("expected an enabled budget")
	}
	p := b.WrapProvider(usageProvider{in: 40, out: 10, text: "hello"})
	drainUsage(t, p)
	drainUsage(t, p)
	if tokens, _, reason := b.Snapshot(); tokens != 100 || reason != "" {
		t.Fatalf("tokens = %d, reason = %q; want 100 and no exhaustion", tokens, reason)
	}
	for i := 0; i < 18; i++ {
		drainUsage(t, p)
	}
	if _, _, reason := b.Snapshot(); !strings.Contains(reason, "token budget exhausted") {
		t.Fatalf("reason = %q; want token budget exhaustion", reason)
	}
}

// Tool calls are counted, refuse to execute past the cap, and write-back tools stay
// available so a budget-exhausted run can still persist results.
func TestBudgetRefusesToolsButAllowsWriteBack(t *testing.T) {
	b := NewRunBudgetLimits(BudgetLimits{MaxToolCalls: 2})
	ran, wrote := 0, 0
	tools := wrapBudgetTools([]actool.CoreTool{
		countingTool("Bash", &ran),
		countingTool("insert_assets", &wrote),
	}, b)
	if len(tools) != 2 {
		t.Fatalf("wrapped tools = %d; want 2", len(tools))
	}
	for i := 0; i < 4; i++ {
		if _, err := tools[0].Call(context.Background(), json.RawMessage(`{}`), nil); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if ran != 2 {
		t.Fatalf("Bash ran %d times; want 2 (budget cap)", ran)
	}
	// Write-back tools bypass the gate.
	res, err := tools[1].Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("write-back call: %v", err)
	}
	if res.IsError {
		t.Fatalf("write-back tool should succeed after exhaustion, got %+v", res)
	}
	if wrote != 1 {
		t.Fatalf("insert_assets ran %d times; want 1", wrote)
	}
}

// A refusal must surface the exhausted dimension so the model knows why.
func TestBudgetRefusalMessage(t *testing.T) {
	b := NewRunBudgetLimits(BudgetLimits{MaxToolCalls: 1})
	ok, _ := b.TakeToolCall("Bash")
	if !ok {
		t.Fatal("first call should be allowed")
	}
	ok, msg := b.TakeToolCall("Bash")
	if ok {
		t.Fatal("second call should be refused")
	}
	if !strings.Contains(msg, "tool-call budget exhausted") || !strings.Contains(msg, "write back") {
		t.Fatalf("guidance = %q", msg)
	}
}

// Unconfigured agents must get a nil budget (no wrappers, no behavior change).
func TestNewRunBudgetDisabled(t *testing.T) {
	old := BudgetOverride
	BudgetOverride = nil
	defer func() { BudgetOverride = old }()
	if b := NewRunBudget("worker"); b != nil {
		t.Fatalf("budget = %+v; want nil when nothing is configured", b)
	}
	BudgetOverride = func(string) (BudgetLimits, bool) { return BudgetLimits{}, true }
	if b := NewRunBudget("worker"); b != nil {
		t.Fatalf("budget = %+v; want nil for all-zero limits", b)
	}
	BudgetOverride = func(string) (BudgetLimits, bool) { return BudgetLimits{MaxTokens: 5}, true }
	if b := NewRunBudget("worker"); b == nil || b.Limits().MaxTokens != 5 {
		t.Fatalf("budget = %+v; want configured limits", b)
	}
}
