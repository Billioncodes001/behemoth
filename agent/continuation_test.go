package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func TestReporterNeverNudgedIntoLiveScanOrInsertAssets(t *testing.T) {
	manualPrompt := "[Manual Report & Reproduction Steps Generation] Author a comprehensive, structured technical vulnerability report in English for tax-database.oirs.ng"
	msgs := []llm.Message{
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock(manualPrompt)}},
		{
			Role: llm.RoleAssistant,
			Content: []llm.ContentBlock{{
				Type:  llm.BlockToolUse,
				ID:    "call_upd",
				Name:  "update_finding_report",
				Input: json.RawMessage(`{"finding_id":2,"report":"## Overview\nSaved"}`),
			}},
		},
		{
			Role: llm.RoleUser,
			Content: []llm.ContentBlock{{
				Type:      llm.BlockToolResult,
				ToolUseID: "call_upd",
				Content:   []llm.ContentBlock{llm.TextBlock("finding 2 report saved")},
			}},
		},
		{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("The detailed vulnerability report has been saved to Finding #2.")},
		},
	}

	bound := map[string]bool{
		"get_finding_traffic":   true,
		"get_finding_record":    true,
		"update_finding_report": true,
		"check_proxy_status":    true,
	}
	shouldNudge, msg := IsPrematureActionTurnForAgent("reporter", bound, msgs, manualPrompt)
	if shouldNudge {
		t.Fatalf("reporter must finish cleanly after saving report, got unexpected nudge: %q", msg)
	}
}

func TestAutoQuestionDoesNotTriggerMandatoryLiveScan(t *testing.T) {
	for _, q := range []string{
		"Where is the vulnerability report saved?",
		"What vulnerabilities did we find so far?",
		"Explain the SQL injection scan results",
	} {
		msgs := []llm.Message{
			{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock(q)}},
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("The report is saved on the Finding Detail page (/function/findings/detail?id=2) and in Workspace under reports/finding-2-report.md.")}},
		}
		shouldNudge, nudge := IsPrematureActionTurnForAgent("auto", map[string]bool{"insert_assets": true}, msgs, q)
		if shouldNudge {
			t.Fatalf("read-only question %q must not trigger live scan nudge, got: %q", q, nudge)
		}
	}
}

func TestAutoTargetScanStillRequiresExecutionTools(t *testing.T) {
	prompt := "Scan https://tax-database.oirs.ng for vulnerabilities using all tools"
	msgs := []llm.Message{
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock(prompt)}},
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("## Summary\nNo issues found (simulated without running tools).")}},
	}
	shouldNudge, nudge := IsPrematureActionTurnForAgent("auto", map[string]bool{"insert_assets": true, "Bash": true}, msgs, prompt)
	if !shouldNudge || !strings.Contains(nudge, "Mandatory Live Execution") {
		t.Fatalf("expected Mandatory Live Execution nudge for unexecuted target scan, got shouldNudge=%v msg=%q", shouldNudge, nudge)
	}
}

func TestDynamicProxyEnvToolUpdatesMidTurn(t *testing.T) {
	currentProxy := ""
	var capturedEnv []string
	dummy := actool.Build(actool.Spec{
		Name:        "ProbeEnv",
		Description: "captures tc.Env",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, _ json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			if tc != nil {
				capturedEnv = append([]string(nil), tc.Env...)
			}
			return actool.Text("ok"), nil
		},
	})

	wrapped := wrapDynamicProxyEnvTools([]actool.CoreTool{dummy}, func() string { return currentProxy }, "")[0]

	// 1. Proxy disabled -> zero HTTP_PROXY env vars!
	_, _ = wrapped.Call(context.Background(), json.RawMessage(`{}`), &actool.ToolContext{
		Env: []string{"FOO=bar", "HTTP_PROXY=http://stale:8080"},
	})
	for _, kv := range capturedEnv {
		if strings.HasPrefix(strings.ToUpper(kv), "HTTP_PROXY=") {
			t.Fatalf("expected HTTP_PROXY stripped when proxy disabled, got env=%v", capturedEnv)
		}
	}

	// 2. Proxy enabled mid-turn -> immediately injected on next tool call!
	currentProxy = "http://127.0.0.1:49152"
	_, _ = wrapped.Call(context.Background(), json.RawMessage(`{}`), &actool.ToolContext{
		Env: []string{"FOO=bar"},
	})
	found := false
	for _, kv := range capturedEnv {
		if kv == "HTTP_PROXY=http://127.0.0.1:49152" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HTTP_PROXY injected after mid-turn activation, got env=%v", capturedEnv)
	}
}
