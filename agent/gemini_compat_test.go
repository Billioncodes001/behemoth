package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestPrepareRequestPreservesHighMaxTokensForReasoningModels(t *testing.T) {
	req := prepareRequest(llm.CompletionRequest{
		MaxTokens: 65536,
		Messages:  []llm.Message{llm.UserText("scan target")},
	})
	if req.MaxTokens != 65536 {
		t.Fatalf("expected MaxTokens=65536 preserved, got %d", req.MaxTokens)
	}
}

func TestGeminiCompatThoughtSignatureAndThoughtRoutingEndToEnd(t *testing.T) {
	var turn int
	var secondTurnBody map[string]any

	mockUpstream := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		turn++
		rawReq, _ := io.ReadAll(req.Body)
		if turn == 1 {
			var parsed map[string]any
			if err := json.Unmarshal(rawReq, &parsed); err != nil {
				t.Fatalf("turn 1 invalid JSON: %v", err)
			}
			// Verify MaxTokens=65536 is NOT clamped to 4096 and Gemini extra_body is injected.
			if mt, _ := parsed["max_tokens"].(float64); int(mt) != 65536 {
				t.Fatalf("expected max_tokens=65536 on turn 1, got %v", parsed["max_tokens"])
			}
			if parsed["extra_body"] == nil {
				t.Fatalf("expected extra_body.google injected on Gemini request")
			}

			sse := strings.Join([]string{
				`data: {"choices":[{"index":0,"delta":{"content":"Inspecting target headers first.","extra_content":{"google":{"thought":true}}}}]}`,
				`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_gemini_1","type":"function","extra_content":{"google":{"thought_signature":"SIG_ENCRYPTED_ABC123"}},"function":{"name":"Bash","arguments":"{\"command\":\"curl -I https://example.com\"}"}}]}}]}`,
				`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: [DONE]`,
				"",
			}, "\n\n")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(sse)),
			}, nil
		}

		if err := json.Unmarshal(rawReq, &secondTurnBody); err != nil {
			t.Fatalf("turn 2 invalid JSON: %v", err)
		}
		sse2 := strings.Join([]string{
			`data: {"choices":[{"index":0,"delta":{"content":"## Security Audit Summary\n\n### Findings\nAll checks completed."}}]}`,
			`data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
			`data: [DONE]`,
			"",
		}, "\n\n")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(sse2)),
		}, nil
	})

	cfg := Config{
		Format:          llm.FormatOpenAI,
		BaseURL:         "https://generativelanguage.googleapis.com/v1beta/openai",
		APIKey:          "test-key",
		Model:           "gemini-4-argon",
		ReasoningEffort: "high",
	}
	client := &http.Client{Transport: mockUpstream}
	prov, err := cfg.newProvider(client, &RequestLimiter{})
	if err != nil {
		t.Fatalf("newProvider: %v", err)
	}

	var gotThinking, gotText string
	var gotToolID, gotToolName, gotToolArgs string
	for ev, err := range prov.Stream(context.Background(), llm.CompletionRequest{
		MaxTokens: 65536,
		Messages:  []llm.Message{llm.UserText("Check https://example.com")},
		Tools: []llm.ToolSchema{{
			Name: "Bash",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"command": map[string]any{"type": "string"}},
				"required":   []any{"command"},
			},
		}},
	}) {
		if err != nil {
			t.Fatalf("turn 1 stream err: %v", err)
		}
		switch ev.Type {
		case llm.SEThinkingDelta:
			gotThinking += ev.Text
		case llm.SETextDelta:
			gotText += ev.Text
		case llm.SEToolUseStart:
			gotToolID, gotToolName = ev.ToolID, ev.ToolName
		case llm.SEToolInputJSON:
			gotToolArgs += ev.Text
		}
	}

	if gotThinking != "Inspecting target headers first." {
		t.Fatalf("expected Gemini thought routed to SEThinkingDelta, got thinking=%q text=%q", gotThinking, gotText)
	}
	if gotText != "" {
		t.Fatalf("expected Gemini thought NOT leaked into SETextDelta, got %q", gotText)
	}
	if gotToolID != "call_gemini_1" || gotToolName != "Bash" {
		t.Fatalf("unexpected tool call: id=%q name=%q args=%q", gotToolID, gotToolName, gotToolArgs)
	}

	// Turn 2: replay assistant tool call + tool result and verify thought_signature is echoed and reasoning_content is stripped.
	turn2Msgs := []llm.Message{
		llm.UserText("Check https://example.com"),
		{
			Role: llm.RoleAssistant,
			Content: []llm.ContentBlock{
				{Type: llm.BlockThinking, Thinking: gotThinking},
				{Type: llm.BlockToolUse, ID: gotToolID, Name: gotToolName, Input: json.RawMessage(gotToolArgs)},
			},
		},
		{
			Role:    llm.RoleUser,
			Content: []llm.ContentBlock{llm.ToolResultText(gotToolID, "HTTP/2 200 OK", false)},
		},
	}
	var turn2Text string
	for ev, err := range prov.Stream(context.Background(), llm.CompletionRequest{
		MaxTokens: 65536,
		Messages:  turn2Msgs,
	}) {
		if err != nil {
			t.Fatalf("turn 2 stream err: %v", err)
		}
		if ev.Type == llm.SETextDelta {
			turn2Text += ev.Text
		}
	}
	if !strings.Contains(turn2Text, "Security Audit Summary") {
		t.Fatalf("unexpected turn 2 text: %q", turn2Text)
	}

	msgsRaw, _ := json.Marshal(secondTurnBody["messages"])
	if bytes.Contains(msgsRaw, []byte("reasoning_content")) {
		t.Fatalf("Gemini outbound messages must not contain reasoning_content: %s", string(msgsRaw))
	}
	if !bytes.Contains(msgsRaw, []byte("SIG_ENCRYPTED_ABC123")) {
		t.Fatalf("expected thought_signature SIG_ENCRYPTED_ABC123 replayed on assistant tool_calls, got: %s", string(msgsRaw))
	}
}

func TestContentFilterStopSurfacesClearExplanationAfterReframeRetry(t *testing.T) {
	calls := 0
	mockBlocked := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		sse := fmt.Sprintf("data: {\"promptFeedback\":{\"blockReason\":\"PROHIBITED_CONTENT\"}}\n\ndata: [DONE]\n\n")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(sse)),
		}, nil
	})

	cfg := Config{
		Format:  llm.FormatOpenAI,
		BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
		APIKey:  "test-key",
		Model:   "gemini-4-argon",
	}
	prov, err := cfg.newProvider(&http.Client{Transport: mockBlocked}, &RequestLimiter{})
	if err != nil {
		t.Fatal(err)
	}

	var gotText string
	var gotStop string
	for ev, err := range prov.Stream(context.Background(), llm.CompletionRequest{
		MaxTokens: 65536,
		Messages:  []llm.Message{llm.UserText("scan target")},
	}) {
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if ev.Type == llm.SETextDelta {
			gotText += ev.Text
		}
		if ev.Type == llm.SEMessageDelta {
			gotStop = ev.StopReason
		}
	}
	if calls != 2 {
		t.Fatalf("expected 1 initial attempt + 1 reframed retry = 2 calls, got %d", calls)
	}
	if !strings.Contains(gotText, "[Provider Safety Filter]") || gotStop != "end_turn" {
		t.Fatalf("expected clear Provider Safety Filter notice and end_turn, got stop=%q text=%q", gotStop, gotText)
	}
}
