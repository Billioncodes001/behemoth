package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// A scripted scenario must drive a complete offline agent loop: tool call → tool
// result → final text, with no network and no API key.
func TestMockProviderOfflineSession(t *testing.T) {
	var echoed []string
	echo := actool.Build(actool.Spec{
		Name:        "echo",
		Description: "echo back the input",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"text": map[string]any{"type": "string"}},
		},
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var args struct{ Text string }
			_ = json.Unmarshal(in, &args)
			echoed = append(echoed, args.Text)
			return actool.Text("echo:" + args.Text), nil
		},
	})
	scenario := MockScenario{
		Turns: []MockTurn{
			{Text: "Probing the endpoint.", Tools: []MockToolCall{{Name: "echo", Input: json.RawMessage(`{"text":"ping"}`)}}},
			{Text: "Done: the probe returned ping."},
		},
	}
	s := agentcore.NewSession(agentcore.Options{
		Provider:       NewMockProvider(scenario),
		Tools:          []actool.CoreTool{echo},
		PermissionMode: permission.ModeBypass,
		WorkingDir:     t.TempDir(),
		MaxTurns:       5,
	})
	defer s.Close()

	var text strings.Builder
	var toolCalls, toolResults int
	var reason harness.TerminalReason
	for ev, err := range s.Prompt(context.Background(), "probe the target") {
		if err != nil {
			t.Fatalf("prompt: %v", err)
		}
		switch ev.Kind {
		case harness.KindText:
			text.WriteString(ev.Text)
		case harness.KindToolUse:
			toolCalls++
		case harness.KindToolResult:
			toolResults++
		case harness.KindResult:
			if ev.Terminal != nil {
				reason = ev.Terminal.Reason
			}
		}
	}
	if len(echoed) != 1 || echoed[0] != "ping" {
		t.Fatalf("echo tool ran with %v; want one call with ping", echoed)
	}
	if toolCalls != 1 || toolResults != 1 {
		t.Fatalf("tool events = %d/%d; want 1/1", toolCalls, toolResults)
	}
	if !strings.Contains(text.String(), "Done: the probe returned ping.") {
		t.Fatalf("final text = %q", text.String())
	}
	if reason != harness.ReasonCompleted {
		t.Fatalf("terminal reason = %q; want completed", reason)
	}
}

// A match turn is selected by the latest user message, not by position.
func TestMockProviderMatchSelection(t *testing.T) {
	p := NewMockProvider(MockScenario{Turns: []MockTurn{
		{Text: "first"},
		{Match: "please verify", Text: "verified"},
	}})
	req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("PLEASE VERIFY the third party")}}
	var got strings.Builder
	for ev, err := range p.Stream(context.Background(), req) {
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		if ev.Type == llm.SETextDelta {
			got.WriteString(ev.Text)
		}
	}
	if got.String() != "verified" {
		t.Fatalf("text = %q; want match-selected turn", got.String())
	}
}

// The non-streaming path must assemble the same scripted turn.
func TestMockProviderComplete(t *testing.T) {
	p := NewMockProvider(MockScenario{Turns: []MockTurn{{Text: "hello", Tools: []MockToolCall{{Name: "Bash"}}}}})
	msg, stop, usage, err := p.Complete(context.Background(), llm.CompletionRequest{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if stop != "tool_use" || len(msg.Content) != 2 || msg.Content[1].Name != "Bash" {
		t.Fatalf("message = %+v (stop %q); want text + Bash tool_use", msg.Content, stop)
	}
	if usage.OutputTokens == 0 {
		t.Fatal("expected non-zero usage")
	}
}

// Provider selection: ConfigFrom("mock") and BEHEMOTH_LLM_PROVIDER=mock must both
// resolve to the offline provider without keys.
func TestMockProviderViaConfig(t *testing.T) {
	t.Setenv("BEHEMOTH_MOCK_RESPONSES", `["offline answer"]`)
	c := ConfigFrom("mock", "", "", "", "")
	if c.Provider() != "mock" {
		t.Fatalf("provider = %q; want mock", c.Provider())
	}
	p, err := c.NewProvider()
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if _, ok := p.(*MockProvider); !ok {
		t.Fatalf("provider type = %T; want *MockProvider", p)
	}

	t.Setenv("BEHEMOTH_LLM_PROVIDER", "mock")
	envCfg, ok := FromEnv()
	if !ok || envCfg.Provider() != "mock" {
		t.Fatalf("FromEnv = %+v, %v; want mock provider without keys", envCfg, ok)
	}
}
