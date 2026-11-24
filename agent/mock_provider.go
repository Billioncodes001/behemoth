package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/llm"
)

// Mock / scenario provider. Offline demos, CI and unit tests need a full agent
// loop without a network or an API key. This provider replays a scripted list of
// turns: each turn can emit text and/or tool calls, exactly like a real model.
//
// Selection is deterministic:
//   - the first not-yet-used turn whose Match substring appears in the latest
//     user message wins;
//   - otherwise turns are consumed in order;
//   - once the script is exhausted the last turn repeats (bounded by MaxTurns).
//
// Wire it with provider "mock" and BEHEMOTH_MOCK_SCENARIO=<path to JSON> (or
// BEHEMOTH_MOCK_RESPONSES=<inline JSON array>). See docs/mock-provider.md.

// MockToolCall is one scripted tool invocation.
type MockToolCall struct {
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input,omitempty"`
}

// MockTurn is one scripted assistant turn.
type MockTurn struct {
	// Match, when non-empty, selects this turn if it appears (case-insensitively)
	// in the latest user message and the turn has not been used yet.
	Match string         `json:"match,omitempty"`
	Text  string         `json:"text,omitempty"`
	Tools []MockToolCall `json:"tools,omitempty"`
}

// MockScenario is the JSON script consumed by the mock provider.
type MockScenario struct {
	Model    string     `json:"model,omitempty"`
	Defaults string     `json:"default_text,omitempty"`
	Turns    []MockTurn `json:"turns"`
}

// MockProvider replays a MockScenario. Safe for concurrent use.
type MockProvider struct {
	mu       sync.Mutex
	scenario MockScenario
	used     []bool
	next     int
	calls    int
}

// NewMockProvider builds a provider over a scenario. An empty scenario answers
// with Defaults (or a fixed notice).
func NewMockProvider(sc MockScenario) *MockProvider {
	if sc.Model == "" {
		sc.Model = "mock-1"
	}
	if sc.Defaults == "" {
		sc.Defaults = "MOCK: no further responses configured."
	}
	return &MockProvider{scenario: sc, used: make([]bool, len(sc.Turns))}
}

// MockProviderFromEnv builds a mock provider from BEHEMOTH_MOCK_SCENARIO (file) or
// BEHEMOTH_MOCK_RESPONSES (inline JSON: either a scenario object or a string array of
// plain-text turns).
func MockProviderFromEnv() (*MockProvider, error) {
	if path := strings.TrimSpace(os.Getenv("BEHEMOTH_MOCK_SCENARIO")); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("mock scenario %s: %w", path, err)
		}
		sc, err := ParseMockScenario(raw)
		if err != nil {
			return nil, fmt.Errorf("mock scenario %s: %w", path, err)
		}
		return NewMockProvider(sc), nil
	}
	if inline := strings.TrimSpace(os.Getenv("BEHEMOTH_MOCK_RESPONSES")); inline != "" {
		sc, err := ParseMockScenario([]byte(inline))
		if err != nil {
			return nil, fmt.Errorf("BEHEMOTH_MOCK_RESPONSES: %w", err)
		}
		return NewMockProvider(sc), nil
	}
	return NewMockProvider(MockScenario{}), nil
}

// ParseMockScenario accepts either a scenario object or a bare array of strings
// (each string becomes a text-only turn).
func ParseMockScenario(raw []byte) (MockScenario, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var texts []string
		if err := json.Unmarshal(raw, &texts); err == nil {
			turns := make([]MockTurn, 0, len(texts))
			for _, t := range texts {
				turns = append(turns, MockTurn{Text: t})
			}
			return MockScenario{Turns: turns}, nil
		}
	}
	var sc MockScenario
	if err := json.Unmarshal(raw, &sc); err != nil {
		return MockScenario{}, err
	}
	return sc, nil
}

// pick chooses the next turn. Callers hold p.mu.
func (p *MockProvider) pick(messages []llm.Message) MockTurn {
	lastUser := ""
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == llm.RoleUser {
			lastUser = strings.ToLower(messages[i].Text())
			break
		}
	}
	if lastUser != "" {
		for i, turn := range p.scenario.Turns {
			if p.used[i] || turn.Match == "" {
				continue
			}
			if strings.Contains(lastUser, strings.ToLower(turn.Match)) {
				p.used[i] = true
				return turn
			}
		}
	}
	for p.next < len(p.scenario.Turns) {
		i := p.next
		p.next++
		if p.used[i] {
			continue
		}
		p.used[i] = true
		return p.scenario.Turns[i]
	}
	if n := len(p.scenario.Turns); n > 0 {
		return p.scenario.Turns[n-1]
	}
	return MockTurn{Text: p.scenario.Defaults}
}

// estimateTokens is the coarse 4-chars-per-token heuristic used for usage
// reporting; the number only needs to be plausible for budget accounting.
func estimateTokens(text string) int {
	if text == "" {
		return 0
	}
	if n := len(text) / 4; n > 0 {
		return n
	}
	return 1
}

// Stream replays the picked turn as normalized events: text delta(s), one
// tool_use start+input per scripted call, a message_delta carrying the stop
// reason and estimated usage, then message_stop.
func (p *MockProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.mu.Lock()
		turn := p.pick(req.Messages)
		p.calls++
		p.mu.Unlock()

		var prompt strings.Builder
		for _, seg := range req.System {
			prompt.WriteString(seg)
		}
		for _, m := range req.Messages {
			prompt.WriteString(m.Text())
		}
		inputTokens := estimateTokens(prompt.String())
		outputTokens := estimateTokens(turn.Text)

		if !yield(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: inputTokens}}, nil) {
			return
		}
		if turn.Text != "" {
			for _, chunk := range chunkText(turn.Text, 200) {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: chunk}, nil) {
					return
				}
			}
		}
		for i, call := range turn.Tools {
			input := call.Input
			if len(input) == 0 {
				input = json.RawMessage("{}")
			}
			toolID := fmt.Sprintf("mock_tool_%d_%d", p.calls, i)
			if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: toolID, ToolName: call.Name}, nil) {
				return
			}
			if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(input)}, nil) {
				return
			}
			outputTokens += estimateTokens(string(input))
		}
		stopReason := "end_turn"
		if len(turn.Tools) > 0 {
			stopReason = "tool_use"
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stopReason,
			Usage: llm.Usage{OutputTokens: outputTokens}}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

// Complete is the non-streaming counterpart: it assembles the same turn into one
// assistant message.
func (p *MockProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.mu.Lock()
	turn := p.pick(req.Messages)
	p.calls++
	p.mu.Unlock()

	blocks := make([]llm.ContentBlock, 0, len(turn.Tools)+1)
	if turn.Text != "" {
		blocks = append(blocks, llm.TextBlock(turn.Text))
	}
	var prompt strings.Builder
	for _, seg := range req.System {
		prompt.WriteString(seg)
	}
	outputTokens := estimateTokens(turn.Text)
	for i, call := range turn.Tools {
		input := call.Input
		if len(input) == 0 {
			input = json.RawMessage("{}")
		}
		blocks = append(blocks, llm.ContentBlock{
			Type:  llm.BlockToolUse,
			ID:    fmt.Sprintf("mock_tool_%d_%d", p.calls, i),
			Name:  call.Name,
			Input: input,
		})
		outputTokens += estimateTokens(string(input))
	}
	for _, m := range req.Messages {
		prompt.WriteString(m.Text())
	}
	usage := llm.Usage{InputTokens: estimateTokens(prompt.String()), OutputTokens: outputTokens}
	stop := "end_turn"
	if len(turn.Tools) > 0 {
		stop = "tool_use"
	}
	return llm.Message{Role: llm.RoleAssistant, Content: blocks}, stop, usage, nil
}

// Calls returns how many model calls the provider has served (tests, demo logs).
func (p *MockProvider) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// chunkText splits s into chunks of at most n bytes on rune boundaries, so the
// replay exercises the same streaming path a real provider does.
func chunkText(s string, n int) []string {
	if n <= 0 || len(s) <= n {
		return []string{s}
	}
	out := []string{}
	for len(s) > n {
		cut := n
		for cut > 0 && (s[cut]&0xC0) == 0x80 { // don't split a UTF-8 sequence
			cut--
		}
		out = append(out, s[:cut])
		s = s[cut:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}
