package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent/payloads"
	"github.com/Autumn-27/norma/llm"
)

func TestSanitizeToolInput_SkillAndParameterTags(t *testing.T) {
	skillSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string"},
			"args": map[string]any{"type": "string"},
		},
		"required": []any{"name"},
	}

	// Exact input from the user screenshot:
	raw := json.RawMessage(`{"skill": "<parameter=skill>\nweb-vuln-exploitation"}`)
	got := SanitizeToolInput("Skill", raw, skillSchema)

	var parsed map[string]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("failed to unmarshal sanitized JSON %s: %v", string(got), err)
	}
	if parsed["name"] != "web-vuln-exploitation" {
		t.Fatalf("expected name=web-vuln-exploitation, got %q (full=%s)", parsed["name"], string(got))
	}
	if _, hasSkill := parsed["skill"]; hasSkill {
		t.Fatalf("expected alias 'skill' to be removed, got %s", string(got))
	}
}

func TestSanitizeToolInput_XMLAndAliases(t *testing.T) {
	bashSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command":     map[string]any{"type": "string"},
			"description": map[string]any{"type": "string"},
		},
		"required": []any{"command"},
	}

	got := SanitizeToolInput("Bash", json.RawMessage(`{"cmd":"<parameter=cmd>\ncurl -I https://example.com</parameter>"}`), bashSchema)
	var parsed map[string]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["command"] != "curl -I https://example.com" {
		t.Fatalf("unexpected command: %q", parsed["command"])
	}
}

func TestIsPrematureActionTurn(t *testing.T) {
	prompt := "scan josiahadeyemo.me for any vulnerabilities, use the necessary tools until you find something"

	// 1. Exact stop from screenshot: "Let me check the current status of the task." after tool error
	msgsAfterErr := []llm.Message{
		llm.UserText(prompt),
		{
			Role: llm.RoleAssistant,
			Content: []llm.ContentBlock{
				{Type: llm.BlockToolUse, ID: "c1", Name: "Skill", Input: json.RawMessage(`{"name":"web-vuln-exploitation"}`)},
			},
		},
		{
			Role: llm.RoleUser,
			Content: []llm.ContentBlock{
				llm.ToolResultText("c1", `Error: invalid tool input: input: missing required property "name"`, true),
			},
		},
		{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("Let me check the current status of the task.\n\n")},
		},
	}
	if ok, nudge := IsPrematureActionTurn(msgsAfterErr, prompt); !ok || nudge == "" {
		t.Fatalf("expected premature stop after tool error to be detected, got ok=%v nudge=%q", ok, nudge)
	}

	// 2. Announcement without tool call: "You're right. Let me run the scan now."
	msgsAnnounce := []llm.Message{
		llm.UserText(prompt),
		{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("You're right. Let me run the scan now.")},
		},
	}
	if ok, _ := IsPrematureActionTurn(msgsAnnounce, prompt); !ok {
		t.Fatal("expected 'Let me run the scan now.' without tool call to be detected as premature")
	}

	// 3. Normal conversational greeting should NOT be flagged as premature
	msgsNormal := []llm.Message{
		llm.UserText("How are you?"),
		{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("I am doing well and ready to assist with your security operations.")},
		},
	}
	if ok, nudge := IsPrematureActionTurn(msgsNormal, "How are you?"); ok {
		t.Fatalf("normal greeting should not be nudged, got nudge=%q", nudge)
	}

	// 4. Hallucinated report with 0 execution turns should be flagged as premature
	msgsHallucinatedReport := []llm.Message{
		llm.UserText(prompt),
		{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("## Vulnerability Scan Summary\n\n### Findings\n- Fabricated summary with zero Bash calls.")},
		},
	}
	if ok, _ := IsPrematureActionTurn(msgsHallucinatedReport, prompt); !ok {
		t.Fatal("expected report with 0 execution turns to be flagged as premature")
	}

	// 5. Final structured report after 3+ execution turns + insert_assets should NOT be flagged as premature
	bashTurn := llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{
			{Type: llm.BlockToolUse, ID: "b1", Name: "Bash", Input: json.RawMessage(`{"command":"curl -I https://josiahadeyemo.me"}`)},
		},
	}
	assetTurn := llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{
			{Type: llm.BlockToolUse, ID: "a1", Name: "insert_assets", Input: json.RawMessage(`{"domain":"josiahadeyemo.me"}`)},
		},
	}
	msgsFinalReport := []llm.Message{
		llm.UserText(prompt),
		bashTurn,
		bashTurn,
		bashTurn,
		assetTurn,
		{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("## Vulnerability Scan Summary\n\n### Findings\n- Confirmed missing security headers and exposed endpoints on josiahadeyemo.me.")},
		},
	}
	cleanHooks := WrapContinuationHooks(nil, prompt, "test", 3)
	if prevent, blocking, _ := cleanHooks.Stop(context.Background(), msgsFinalReport); prevent || len(blocking) > 0 {
		t.Fatalf("final report after 3 exec turns + insert_assets should not be blocked: prevent=%v blocking=%v", prevent, blocking)
	}
}

func TestExtractBracketToolCalls_AndThinking(t *testing.T) {
	tools := []llm.ToolSchema{
		{
			Name: "Bash",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command": map[string]any{"type": "string"},
				},
				"required": []any{"command"},
			},
		},
		{
			Name: "WebFetch",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string"},
				},
				"required": []any{"url"},
			},
		},
	}

	raw := "<think>\nLet me check the site first.\n</think>\nStarting the scan of prankshitstudio.com.\n[Called tool Bash({\"command\":\"dig +short prankshitstudio.com A\"})]\n[Called tool WebFetch with: {\"url\":\"http://prankshitstudio.com/\"}]"
	cleanTxt, calls := extractEmbeddedToolCalls(raw, tools)
	if len(calls) != 2 {
		t.Fatalf("expected 2 extracted tool calls, got %d", len(calls))
	}
	if calls[0].Name != "Bash" || string(calls[0].Input) != `{"command":"dig +short prankshitstudio.com A"}` {
		t.Fatalf("unexpected call[0]: %+v (%s)", calls[0], string(calls[0].Input))
	}
	if calls[1].Name != "WebFetch" || string(calls[1].Input) != `{"url":"http://prankshitstudio.com/"}` {
		t.Fatalf("unexpected call[1]: %+v (%s)", calls[1], string(calls[1].Input))
	}
	thinkTxt, finalClean := extractThinkingFromText(cleanTxt)
	if thinkTxt != "Let me check the site first." {
		t.Fatalf("expected thinking extracted, got %q", thinkTxt)
	}
	if finalClean != "Starting the scan of prankshitstudio.com." {
		t.Fatalf("expected clean text without tool calls or think tags, got %q", finalClean)
	}
}

func TestPayloadGenerators_NoFormatErrors(t *testing.T) {
	cc, err := payloads.GenerateCCSkimmer(payloads.CCSkimmerConfig{ExfilURL: "https://example.com/collect"})
	if err != nil || strings.Contains(cc, "%!") {
		t.Fatalf("CCSkimmer error or fmt artifact: err=%v payload=%s", err, cc)
	}
	ck, err := payloads.GenerateCookieExfil(payloads.CookieExfilConfig{ExfilURL: "https://example.com/cookie"})
	if err != nil || strings.Contains(ck, "%!") {
		t.Fatalf("CookieExfil error or fmt artifact: err=%v payload=%s", err, ck)
	}
	dom, err := payloads.GenerateCryptoSwapDOM(payloads.CryptoSwapConfig{AttackerBTC: "bc1qtest", AttackerETH: "0x1234"})
	if err != nil || strings.Contains(dom, "%!") {
		t.Fatalf("CryptoSwapDOM error or fmt artifact: err=%v payload=%s", err, dom)
	}
	clip, err := payloads.GenerateClipboardHijack(payloads.CryptoSwapConfig{AttackerETH: "0x1234"})
	if err != nil || strings.Contains(clip, "%!") {
		t.Fatalf("ClipboardHijack error or fmt artifact: err=%v payload=%s", err, clip)
	}
	scr, err := payloads.GenerateScreenExfil(payloads.ScreenExfilConfig{ExfilURL: "https://example.com/screen"})
	if err != nil || strings.Contains(scr, "%!") {
		t.Fatalf("ScreenExfil error or fmt artifact: err=%v payload=%s", err, scr)
	}
}
