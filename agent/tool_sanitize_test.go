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

	// 4. Final structured report with headings should NOT be flagged as premature
	msgsFinalReport := []llm.Message{
		llm.UserText(prompt),
		{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("## Vulnerability Scan Summary\n\n### Findings\n- Confirmed missing security headers and exposed endpoints on josiahadeyemo.me.")},
		},
	}
	cleanHooks := WrapContinuationHooks(nil, prompt, "test", 3)
	if prevent, blocking, _ := cleanHooks.Stop(context.Background(), msgsFinalReport); prevent || len(blocking) > 0 {
		t.Fatalf("final report should not be blocked: prevent=%v blocking=%v", prevent, blocking)
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
