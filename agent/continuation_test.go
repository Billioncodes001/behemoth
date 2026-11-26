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

	// 3. Service API keys (2Captcha + Search) saved mid-turn -> immediately injected on next tool call!
	prevExtra := ExtraServiceEnv
	ExtraServiceEnv = func() []string {
		return []string{
			"TWO_CAPTCHA_API_KEY=2cap-live-key",
			"SEARCH_FIRECRAWL_API_KEY=fc-live-key",
			"SEARCH_SEARXNG_URL=http://127.0.0.1:8888",
		}
	}
	defer func() { ExtraServiceEnv = prevExtra }()

	_, _ = wrapped.Call(context.Background(), json.RawMessage(`{}`), &actool.ToolContext{
		Env: []string{"FOO=bar", "TWO_CAPTCHA_API_KEY=old-key"},
	})
	seen2Cap, seenFC := false, false
	for _, kv := range capturedEnv {
		if kv == "TWO_CAPTCHA_API_KEY=old-key" {
			t.Fatalf("stale TWO_CAPTCHA_API_KEY was not replaced: %v", capturedEnv)
		}
		if kv == "TWO_CAPTCHA_API_KEY=2cap-live-key" {
			seen2Cap = true
		}
		if kv == "SEARCH_FIRECRAWL_API_KEY=fc-live-key" {
			seenFC = true
		}
	}
	if !seen2Cap || !seenFC {
		t.Fatalf("expected live 2Captcha & Firecrawl keys in tc.Env, got %v", capturedEnv)
	}
}

func TestAutoDelegatesScanToTaskAndSoloPentestRunsExploitationLoop(t *testing.T) {
	prompt := "Scan this entire website https://tax-database.oirs.ng and exploit all vulnerabilities"
	bound := map[string]bool{
		"Bash":                                   true,
		"run_security_tool":                      true,
		"list_tasks":                             true,
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

	// --- Part A: Default `auto` Super-Agent in /chat delegates to Tasks and stops solo grinding ---
	hooks := WrapChatContinuationHooks(nil, "auto", bound, prompt, "conv-1", 4)
	if blocked, reason, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"nmap -sV tax-database.oirs.ng"}`)); !blocked || !strings.Contains(reason, "Task Orchestration Guard") {
		t.Fatalf("expected PreToolUse to block solo Bash before spawn_task on Auto, got blocked=%v reason=%q", blocked, reason)
	}
	// list_tasks and spawn_task are orchestration tools -> never blocked
	if blocked, _, _ := hooks.PreToolUse(context.Background(), "list_tasks", []byte(`{}`)); blocked {
		t.Fatal("list_tasks must not be blocked on Auto")
	}
	if blocked, _, _ := hooks.PreToolUse(context.Background(), "spawn_task", []byte(`{}`)); blocked {
		t.Fatal("spawn_task must not be blocked on Auto")
	}
	hooks.PostToolUse(context.Background(), "spawn_task", []byte(`{}`), []byte(`task created: 14`), false)
	if blocked, reason, _ := hooks.PreToolUse(context.Background(), "run_security_tool", []byte(`{}`)); !blocked || !strings.Contains(reason, "Task Handoff Complete") {
		t.Fatalf("expected PreToolUse to prevent duplicate solo scanning after spawn_task, got blocked=%v reason=%q", blocked, reason)
	}

	// Only calling list_tasks (read-only) does NOT satisfy task delegation -> nudges spawn_task!
	ltA, ltU := toolTurn("lt1", "list_tasks")
	autoMsgs := []llm.Message{
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock(prompt)}},
		ltA, ltU,
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("## Status\nChecked tasks.")}},
	}
	shouldNudge, nudge := IsPrematureActionTurnForAgent("auto", bound, autoMsgs, prompt)
	if !shouldNudge || !strings.Contains(nudge, "Delegate Assignment to Multi-Agent Tasks") {
		t.Fatalf("expected Delegate Assignment to Multi-Agent Tasks nudge before spawn_task, got shouldNudge=%v msg=%q", shouldNudge, nudge)
	}

	// Once Auto calls spawn_task and presents the handoff summary -> clean immediate stop (0 solo Bash turns needed)!
	spA, spU := toolTurn("sp1", "spawn_task")
	autoMsgs = append(autoMsgs[:len(autoMsgs)-1], spA, spU, llm.Message{
		Role:    llm.RoleAssistant,
		Content: []llm.ContentBlock{llm.TextBlock("## Dispatched to Multi-Agent Tasks\nAssigned to [Task #14](/function/tasks/detail?id=14). Live updates will post back into this Chat automatically.")},
	})
	if shouldNudgeAfter, msgAfter := IsPrematureActionTurnForAgent("auto", bound, autoMsgs, prompt); shouldNudgeAfter {
		t.Fatalf("expected Auto to finish cleanly right after spawn_task handoff, got nudge=%q", msgAfter)
	}

	// Explicit "in chat only / without creating a task" or narrow @[finding#...] -> NOT forced into Tasks
	directPrompt := "Run a quick header check on https://tax-database.oirs.ng in chat only without creating a task"
	directHooks := WrapChatContinuationHooks(nil, "auto", bound, directPrompt, "conv-2", 4)
	if blocked, _, _ := directHooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"curl -I https://tax-database.oirs.ng"}`)); blocked {
		t.Fatal("explicit in-chat-only request must allow direct Bash in Auto")
	}

	// --- Part B: Explicitly selected `pentest` (Solo Pentest) agent still runs full solo assessment + exploitation ---
	t1a, t1u := toolTurn("c1", "Bash")
	t2a, t2u := toolTurn("c2", "Bash")
	t3a, t3u := toolTurn("c3", "Bash")
	t4a, t4u := toolTurn("c4", "insert_assets")
	t5a, t5u := toolTurn("c5", "report_finding")

	pentestMsgs := []llm.Message{
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock(prompt)}},
		t1a, t1u, t2a, t2u, t3a, t3u, t4a, t4u, t5a, t5u,
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("## Summary\nFound 9 surface findings.")}},
	}
	shouldNudge2, nudge2 := IsPrematureActionTurnForAgent("pentest", bound, pentestMsgs, prompt)
	if !shouldNudge2 || !strings.Contains(nudge2, "Mandatory Post-Discovery Exploitation") {
		t.Fatalf("expected Solo Pentest to nudge Mandatory Post-Discovery Exploitation, got shouldNudge=%v msg=%q", shouldNudge2, nudge2)
	}

	arA, arU := toolTurn("c7", "search_patch_arsenal")
	exA, exU := toolTurn("c8", "Bash")
	upA, upU := toolTurn("c9", "update_finding")
	svA, svU := toolTurn("c10", "save_verified_exploit_to_patch_monitor")
	pentestMsgs = append(pentestMsgs[:len(pentestMsgs)-1], arA, arU, exA, exU, upA, upU, svA, svU, llm.Message{
		Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("## Final Report\nAll findings exploited, severities escalated, and PoCs saved to Patch Monitor.")},
	})
	if shouldNudge3, nudge3 := IsPrematureActionTurnForAgent("pentest", bound, pentestMsgs, prompt); shouldNudge3 {
		t.Fatalf("expected clean completion after Solo Pentest exploitation loop, got unexpected nudge: %q", nudge3)
	}
}
