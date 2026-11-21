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

func TestAutoWholeWebsiteScanNudgesSpawnTaskAndPostFindingExploitation(t *testing.T) {
	prompt := "Scan this entire website https://tax-database.oirs.ng and exploit all vulnerabilities"
	bound := map[string]bool{
		"Bash":                                   true,
		"insert_assets":                          true,
		"spawn_task":                             true,
		"report_finding":                         true,
		"search_patch_arsenal":                   true,
		"save_verified_exploit_to_patch_monitor": true,
		"update_finding":                         true,
	}

	toolTurn := func(id, name string) (llm.Message, llm.Message) {
		return llm.Message{
				Role: llm.RoleAssistant,
				Content: []llm.ContentBlock{{
					Type: llm.BlockToolUse, ID: id, Name: name, Input: json.RawMessage(`{}`),
				}},
			}, llm.Message{
				Role: llm.RoleUser,
				Content: []llm.ContentBlock{{
					Type: llm.BlockToolResult, ToolUseID: id, Content: []llm.ContentBlock{llm.TextBlock("ok")},
				}},
			}
	}

	t1a, t1u := toolTurn("c1", "Bash")
	t2a, t2u := toolTurn("c2", "Bash")
	t3a, t3u := toolTurn("c3", "Bash")
	t4a, t4u := toolTurn("c4", "insert_assets")
	t5a, t5u := toolTurn("c5", "report_finding")

	msgs := []llm.Message{
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock(prompt)}},
		t1a, t1u, t2a, t2u, t3a, t3u, t4a, t4u, t5a, t5u,
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("## Summary\nFound 9 surface findings.")}},
	}

	// 1. Missing spawn_task on full-site scan -> nudges Create Engagement Task!
	shouldNudge, nudge := IsPrematureActionTurnForAgent("auto", bound, msgs, prompt)
	if !shouldNudge || !strings.Contains(nudge, "Create Engagement Task") {
		t.Fatalf("expected Create Engagement Task nudge, got shouldNudge=%v msg=%q", shouldNudge, nudge)
	}

	// 2. After calling spawn_task, trying to stop right after report_finding -> nudges Mandatory Post-Discovery Exploitation Loop!
	spA, spU := toolTurn("c6", "spawn_task")
	msgs = append(msgs[:len(msgs)-1], spA, spU, llm.Message{
		Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("## Summary\nTask created and 9 findings reported.")},
	})
	shouldNudge2, nudge2 := IsPrematureActionTurnForAgent("auto", bound, msgs, prompt)
	if !shouldNudge2 || !strings.Contains(nudge2, "Mandatory Post-Discovery Exploitation") {
		t.Fatalf("expected Mandatory Post-Discovery Exploitation nudge, got shouldNudge=%v msg=%q", shouldNudge2, nudge2)
	}

	// 3. Once search_patch_arsenal + live exploitation turns + update_finding/save_verified_exploit_to_patch_monitor complete -> clean stop!
	arA, arU := toolTurn("c7", "search_patch_arsenal")
	exA, exU := toolTurn("c8", "Bash")
	upA, upU := toolTurn("c9", "update_finding")
	svA, svU := toolTurn("c10", "save_verified_exploit_to_patch_monitor")
	msgs = append(msgs[:len(msgs)-1], arA, arU, exA, exU, upA, upU, svA, svU, llm.Message{
		Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("## Final Report\nAll findings exploited, severities escalated, and PoCs saved to Patch Monitor.")},
	})
	shouldNudge3, nudge3 := IsPrematureActionTurnForAgent("auto", bound, msgs, prompt)
	if shouldNudge3 {
		t.Fatalf("expected clean completion after exploitation loop, got unexpected nudge: %q", nudge3)
	}
}
