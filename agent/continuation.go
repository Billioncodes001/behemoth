package agent

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

var (
	reActionIntentAnnouncement     = regexp.MustCompile(`(?i)(?:^|[.!?]\s+|\n\s*)(?:let\s+me\b|let's\b|i\s+will\b|i'll\b|i\s+am\s+going\s+to\b|i'm\s+going\s+to\b|going\s+to\b|starting\s+(?:a\s+|the\s+)?(?:scan|recon|test|probe|check|investigation|analysis|enumeration)|running\s+(?:a\s+|the\s+)?(?:scan|recon|test|probe|check|command|tool)|checking\s+(?:the\s+)?(?:current\s+status|target|site|web|http|headers|ports|endpoints|vulnerabilities)|investigating\s+the\b|scanning\s+the\b|probing\s+the\b|now\s+let\s+me\b|next,?\s+let\s+me\b|next,?\s+i\s+will\b|first,?\s+let\s+me\b|allow\s+me\b)`)
	reActiveTaskPrompt             = regexp.MustCompile(`(?i)\b(scan(?:ning)?|pentest(?:ing)?|penetration\s+test(?:ing)?|exploit(?:ation|ing)?|vulnerabilit(?:y|ies)|recon|reconnaissance|enumerate|probe|audit(?:ing)?|assess(?:ment)?|find\s+something|use\s+.*tools|check\s+.*for\s+vulnerabilit|attack|fuzz|crawl|spider|discover|bug\s*hunt|hunt\s+for\s+bugs)\b`)
	reWholeSiteEngagementPrompt    = regexp.MustCompile(`(?i)\b(scan\s+(?:this|the|entire|whole)?\s*(?:website|site|domain|portal|app|application|target|https?://|[a-z0-9.-]+\.[a-z]{2,})|pentest(?:ing)?|penetration\s+test(?:ing)?|full\s+(?:scan|assessment|audit)|find\s+vulnerabilit.*exploit|scan.*and\s+exploit)\b`)
	reSingleFindingMention         = regexp.MustCompile(`(?i)@\[finding#\d+`)
	reExplicitDirectChatOnlyPrompt = regexp.MustCompile(`(?i)\b(?:in\s+chat\s+only|directly\s+in\s+chat|without\s+(?:creating\s+|spawning\s+|using\s+)?(?:a\s+)?task|don'?t\s+(?:create|spawn|start)\s+(?:a\s+)?task|do\s+not\s+(?:create|spawn|start)\s+(?:a\s+)?task|no\s+task\b)`)
	reSystemReminderBlock          = regexp.MustCompile(`(?is)<system-reminder>.*?</system-reminder>`)
	reTargetHostOrURL              = regexp.MustCompile(`(?i)(?:https?://[^\s/$.?#].[^\s]*|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,24}\b)`)
	reReadOnlyQuestionPrompt       = regexp.MustCompile(`(?is)^\s*(?:\[manual\s+report|manual\s+selection\s+review|where\s+is\b|where\s+are\b|what\s+is\b|what\s+are\b|what\s+vulnerabilit|why\s+did\b|why\s+is\b|how\s+does\b|how\s+is\b|explain\b|summarize\b|show\s+me\s+(?:the\s+)?(?:report|status|findings|task)\b|status\s+of\b)`)
)

const (
	continuationThinkingNudge = "[System Continuation] Your previous turn only produced internal thinking with no visible response and no tool call. Immediately execute your next step by calling the appropriate tool, or provide your final conclusion if all work is complete."

	continuationToolErrorNudge = "[System Continuation] The previous tool call returned an error and you responded with a brief status message without invoking any tool. Do not stop—immediately invoke the corrected tool call or use an alternative tool (e.g., Bash, Skill, WebFetch, insert_assets, spawn_task, report_finding) to continue the operation."

	continuationPrematureIntentNudge = "[System Continuation] You announced an action or next step in text without emitting a tool call. Never stop after a status announcement—immediately invoke the required tool (e.g., Bash, Skill, WebFetch, insert_assets, spawn_task, report_finding) and continue executing step-by-step until the user's request is thoroughly completed."

	continuationNoExecToolsNudge = "[System Continuation — Mandatory Live Execution] You have NOT executed any live reconnaissance or probing tools (such as Bash, WebFetch, or spawn_task) against the target yet—only meta/lookup tools were called. Never fabricate or guess scan results, IPs, headers, or asset IDs! Immediately invoke Bash (e.g., curl, dig, whatweb, nmap, nuclei, ffuf, python3) to perform live testing against the target."

	continuationIncompleteScanNudge = "[System Continuation — Incomplete Vulnerability Assessment] You have only executed %d live probing round(s) so far. The user requested a thorough vulnerability scan using the necessary tools. Do NOT stop early—continue your investigation now by: (1) inspecting the fetched HTML/JS source, links, forms, robots.txt, sitemap.xml, API endpoints, and HTTP security/CORS headers via Bash; (2) checking `search_patch_arsenal` for existing exploits/payloads matching fingerprinted technologies; (3) actively probing discovered endpoints and parameters for vulnerabilities (XSS, SQLi, SSRF, LFI, open redirects, exposed configs/.git/.env); and (4) registering discovered target assets via insert_assets."

	continuationMissingAssetSyncNudge = "[System Continuation — Mandatory Asset Synchronization] Before concluding your assessment, you must call insert_assets to persist the genuinely discovered target domain, IP address(es), open ports, and web services into the BEHEMOTH Assets database (and call report_finding if any real vulnerability was verified). Invoke insert_assets now, then continue."

	continuationMissingSpawnTaskNudge = "[System Continuation — Delegate Assignment to Multi-Agent Tasks] This request is a target scan / security assessment assignment in default Auto Chat. Do NOT grind solo in Chat or stop without dispatching a Task: (1) check `list_tasks` first to see if an active task already exists for this target domain; (2) register target scope (`add_company_scope` / `insert_assets`) if needed; (3) pre-fill a comprehensive Task (`description` + structured `goal`) and call `spawn_task` ONCE (or `add_task_hint` if an active task already exists for this target); and (4) immediately reply in Chat with a clickable `[Task #<id>](/function/tasks/detail?id=<id>)` link informing the user that parallel Multi-Agent Workers are now executing it and will automatically post live finding & completion updates back into this Chat!"

	continuationExploitDiscoveredFindingsNudge = "[System Continuation — Mandatory Post-Discovery Exploitation & Arsenal Loop] You recorded %d candidate finding(s) via `report_finding`, and attempted to stop at surface detection without driving each finding through active exploitation! Do NOT stop until all exploitation paths are genuinely exhausted: (1) call `search_patch_arsenal` to check if Patch Monitor already has CVEs, PoCs, or payloads for the discovered libraries/technologies/vulnerability classes and reuse them; (2) systematically go through EACH recorded finding and execute live PoCs (`Bash`, Playwright/browser MCP, `run_security_tool`) to prove maximum impact and test exploit chains; (3) whenever exploitation proves higher impact or confirms code/script execution, call `update_finding` to escalate `severity` (e.g. `low` -> `medium`/`high`/`critical`), set `status='confirmed'`, and append PoC output, plus `update_finding_report`; and (4) save any newly verified working exploit/payload back to Patch Monitor via `save_verified_exploit_to_patch_monitor`!"
)

func stripSystemReminders(prompt string) string {
	if !strings.Contains(prompt, "<system-reminder>") {
		return prompt
	}
	return strings.TrimSpace(reSystemReminderBlock.ReplaceAllString(prompt, ""))
}

// shouldAutoDelegateToTask reports whether a prompt sent to the default `auto`
// Super-Agent in /chat is an engagement/scan/pentest assignment that should be
// converted into a parallel Multi-Agent Task via spawn_task (rather than burned
// sequentially inside single-agent Chat).
func shouldAutoDelegateToTask(agentKey string, boundTools map[string]bool, prompt string) bool {
	if !strings.EqualFold(strings.TrimSpace(agentKey), "auto") {
		return false
	}
	if boundTools != nil && !boundTools["spawn_task"] {
		return false
	}
	clean := stripSystemReminders(prompt)
	if reExplicitDirectChatOnlyPrompt.MatchString(clean) {
		return false
	}
	// Only exempt a narrow single-finding Q&A/check when there is at most one
	// @[finding#...] reference AND the prompt is NOT a full-site or multi-finding
	// pentest continuation (e.g. "Continue comprehensive penetration testing...").
	findingMentions := reSingleFindingMention.FindAllString(clean, -1)
	if len(findingMentions) == 1 && !reWholeSiteEngagementPrompt.MatchString(clean) &&
		!strings.Contains(strings.ToLower(clean), "reuse task #") &&
		!strings.Contains(strings.ToLower(clean), "add_task_hint") {
		return false
	}
	return isLiveTargetScanPrompt("auto", clean)
}

func IsPrematureActionTurn(messages []llm.Message, initialUserPrompt string) (bool, string) {
	return IsPrematureActionTurnForAgent("", nil, messages, initialUserPrompt)
}

func isActiveProbingAgent(agentKey string) bool {
	if agentKey == "" {
		return true // preserve legacy callers & unit tests that omit agentKey
	}
	switch strings.ToLower(strings.TrimSpace(agentKey)) {
	case "reporter", "asset_mapper", "goals", "credential_processor", "retester", "patch_watch", "proxy_harvester", "bounty_scout", "planner":
		return false
	default:
		return true
	}
}

func isLiveTargetScanPrompt(agentKey, prompt string) bool {
	if !isActiveProbingAgent(agentKey) {
		return false
	}
	trimmed := strings.TrimSpace(stripSystemReminders(prompt))
	if trimmed == "" || reReadOnlyQuestionPrompt.MatchString(trimmed) {
		return false
	}
	if !reActiveTaskPrompt.MatchString(trimmed) {
		return false
	}
	// If agentKey is explicitly set (runtime Chat session), require a concrete target
	// URL/domain/IP in the prompt so conversational questions ("What vulnerabilities did we find?")
	// never trigger mandatory multi-round target scans.
	if agentKey != "" && !reTargetHostOrURL.MatchString(trimmed) {
		return false
	}
	return true
}

func IsPrematureActionTurnForAgent(agentKey string, boundTools map[string]bool, messages []llm.Message, initialUserPrompt string) (bool, string) {
	var lastAsst *llm.Message
	lastAsstIdx := -1
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == llm.RoleAssistant {
			lastAsst = &messages[i]
			lastAsstIdx = i
			break
		}
	}
	if lastAsst == nil || len(lastAsst.ToolUses()) > 0 {
		return false, ""
	}

	text := strings.TrimSpace(lastAsst.Text())
	if strings.Contains(text, "[Provider Safety Filter]") {
		return false, ""
	}
	if text == "" {
		return true, continuationThinkingNudge
	}

	prog := analyzeRunToolProgressSummary(messages)
	if strings.EqualFold(strings.TrimSpace(agentKey), "reporter") && prog.completedReportingGoal {
		// Reporter has already saved its report/review; allow immediate clean completion!
		return false, ""
	}

	prevWasToolError := false
	if lastAsstIdx > 0 {
		prev := messages[lastAsstIdx-1]
		if prev.Role == llm.RoleUser && len(prev.Content) > 0 {
			allErr, hasToolRes := true, false
			for _, b := range prev.Content {
				if b.Type == llm.BlockToolResult {
					hasToolRes = true
					if !b.IsError {
						allErr = false
					}
				}
			}
			if hasToolRes && allErr {
				prevWasToolError = true
			}
		}
	}

	if prevWasToolError && len(text) < 500 && isActiveProbingAgent(agentKey) {
		return true, continuationToolErrorNudge
	}

	hasFinalReportHeadings := strings.Contains(text, "## ") || strings.Contains(text, "### ") || len(text) > 600
	if !hasFinalReportHeadings && len(text) <= 450 {
		if reActionIntentAnnouncement.MatchString(text) || strings.HasSuffix(text, ":") || strings.HasSuffix(text, "...") || strings.HasSuffix(text, "…") {
			return true, continuationPrematureIntentNudge
		}
	}

	// Default Auto Super-Agent in /chat: convert engagement/scan/pentest requests into
	// a parallel Multi-Agent Task via spawn_task (or add_task_hint on an existing task)
	// and finish Chat immediately instead of burning hours/tokens solo in Chat!
	if shouldAutoDelegateToTask(agentKey, boundTools, initialUserPrompt) {
		if prog.calledSpawnTask {
			return false, ""
		}
		if !prog.nudgedSpawnTask {
			return true, continuationMissingSpawnTaskNudge
		}
		return false, ""
	}

	// For active scan / assessment / tool-execution prompts on solo probing agents (e.g. Solo Pentest),
	// verify that real probing tools, asset/task synchronization, AND post-discovery exploitation of
	// discovered findings were actually performed before concluding!
	if isLiveTargetScanPrompt(agentKey, initialUserPrompt) {
		if prog.execTurns == 0 {
			return true, continuationNoExecToolsNudge
		}
		if prog.execTurns < 3 {
			return true, fmt.Sprintf(continuationIncompleteScanNudge, prog.execTurns)
		}
		canSyncAssets := boundTools == nil || boundTools["insert_assets"] || boundTools["add_company_scope"] || boundTools["spawn_task"] || boundTools["report_finding"]
		if !prog.calledAssetOrTaskSync && canSyncAssets {
			return true, continuationMissingAssetSyncNudge
		}
		// Post-Discovery Exploitation Loop: if findings were discovered via report_finding,
		// do NOT stop right after surface reporting—require active post-discovery exploitation!
		if prog.reportedFindings > 0 && !prog.nudgedExploitLoop &&
			(prog.execTurnsAfterFirstFinding < 2 || (!prog.checkedPatchArsenal && boundTools != nil && boundTools["search_patch_arsenal"])) {
			return true, fmt.Sprintf(continuationExploitDiscoveredFindingsNudge, prog.reportedFindings)
		}
	}
	return false, ""
}

type runProgressSummary struct {
	execTurns                  int
	calledAssetOrTaskSync      bool
	calledSpawnTask            bool
	completedReportingGoal     bool
	reportedFindings           int
	execTurnsAfterFirstFinding int
	checkedPatchArsenal        bool
	updatedFinding             bool
	nudgedSpawnTask            bool
	nudgedExploitLoop          bool
}

// analyzeRunToolProgress scans messages since the last plain user prompt and counts:
// - execTurns: assistant turns that invoked substantive execution tools
// - calledAssetOrTaskSync: whether insert_assets, add_company_scope, spawn_task, or report_finding was invoked
func analyzeRunToolProgress(messages []llm.Message) (execTurns int, calledAssetOrTaskSync bool) {
	p := analyzeRunToolProgressSummary(messages)
	return p.execTurns, p.calledAssetOrTaskSync
}

func analyzeRunToolProgressDetailed(messages []llm.Message) (execTurns int, calledAssetOrTaskSync bool, completedReportingGoal bool) {
	p := analyzeRunToolProgressSummary(messages)
	return p.execTurns, p.calledAssetOrTaskSync, p.completedReportingGoal
}

func analyzeRunToolProgressSummary(messages []llm.Message) runProgressSummary {
	var p runProgressSummary
	startIdx := 0
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role == llm.RoleUser {
			hasPlainText, hasToolResult := false, false
			for _, b := range m.Content {
				trimmed := strings.TrimSpace(b.Text)
				if b.Type == llm.BlockText && trimmed != "" {
					if strings.Contains(trimmed, "[System Continuation — Create Engagement Task]") ||
						strings.Contains(trimmed, "[System Continuation — Sync Engagement Task]") ||
						strings.Contains(trimmed, "[System Continuation — Delegate Assignment to Multi-Agent Tasks]") {
						p.nudgedSpawnTask = true
					}
					if strings.Contains(trimmed, "[System Continuation — Mandatory Post-Discovery Exploitation") {
						p.nudgedExploitLoop = true
					}
					if !strings.HasPrefix(trimmed, "<system-reminder>") &&
						!strings.HasPrefix(trimmed, "[System Continuation") {
						hasPlainText = true
					}
				}
				if b.Type == llm.BlockToolResult {
					hasToolResult = true
				}
			}
			if hasPlainText && !hasToolResult {
				startIdx = i
				break
			}
		}
	}

	seenFirstFinding := false
	for i := startIdx; i < len(messages); i++ {
		m := messages[i]
		if m.Role != llm.RoleAssistant {
			continue
		}
		uses := m.ToolUses()
		turnHadExec := false
		turnReportedFinding := false
		for _, u := range uses {
			switch u.Name {
			case "Bash", "WebFetch", "web_search", "spawn_task", "ExecuteExtraTool", "shell_open", "shell_send",
				"run_security_tool", "browser_inspect", "verify_xss_execution", "sync_nuclei_templates",
				"detect_deception_and_honeypot", "multi_engine_search", "exploit_search",
				"solve_captcha", "save_artifact", "proxied_tcp_relay", "create_callback_listener", "poll_callback_events",
				"c2_build_implant", "c2_deploy", "c2_agents", "c2_task", "c2_results", "c2_kill",
				"manage_phish_site", "phish_captures",
				"manage_auth_sessions", "verify_access_control_matrix", "audit_frontend_api_surface",
				"verify_endpoint_idempotency", "audit_source_routes",
				"import_and_test_proxies", "manage_proxy_pool", "scrape_online_proxies",
				"add_proxy_scrape_source", "remove_proxy_scrape_source", "verify_and_import_scraped_proxies",
				"match_vuln_targets", "update_exploit_target_status",
				"check_patch_feeds", "add_patch_watch_feed", "discover_affected_sites_for_notification",
				"search_patch_arsenal", "save_verified_exploit_to_patch_monitor",
				"generate_vuln_exploit", "generate_payload", "search_ios_exploits":
				turnHadExec = true
			}
			switch u.Name {
			case "insert_assets", "add_company_scope", "spawn_task", "report_finding",
				"generate_vuln_exploit", "generate_payload", "save_verified_exploit_to_patch_monitor":
				p.calledAssetOrTaskSync = true
			}
			if (u.Name == "spawn_task" || u.Name == "add_task_hint" || u.Name == "set_task_goals") && !toolCallFailedInNextTurn(messages, i, u.ID) {
				p.calledSpawnTask = true
			}
			if u.Name == "report_finding" && !toolCallFailedInNextTurn(messages, i, u.ID) {
				p.reportedFindings++
				turnReportedFinding = true
			}
			if u.Name == "search_patch_arsenal" || u.Name == "save_verified_exploit_to_patch_monitor" {
				p.checkedPatchArsenal = true
			}
			if u.Name == "update_finding" || u.Name == "update_finding_report" {
				p.updatedFinding = true
			}
			switch u.Name {
			case "update_finding_report", "update_finding_case_report", "complete_finding_case_review", "complete_finding_retest":
				if !toolCallFailedInNextTurn(messages, i, u.ID) {
					p.completedReportingGoal = true
				}
			}
		}
		if turnHadExec {
			p.execTurns++
			if seenFirstFinding && !turnReportedFinding {
				p.execTurnsAfterFirstFinding++
			}
		}
		if turnReportedFinding {
			seenFirstFinding = true
		}
	}
	return p
}

func toolCallFailedInNextTurn(messages []llm.Message, asstIdx int, callID string) bool {
	if asstIdx+1 >= len(messages) || callID == "" {
		return false
	}
	for _, b := range messages[asstIdx+1].Content {
		if b.Type == llm.BlockToolResult && b.ToolUseID == callID {
			return b.IsError
		}
	}
	return false
}

type continuationHooks struct {
	inner             harness.HookRunner
	agentKey          string
	boundTools        map[string]bool
	initialUserPrompt string
	label             string
	nudges            atomic.Int64
	maxNudges         int
	taskDispatched    atomic.Bool
	soloProbeAttempts atomic.Int64
}

func WrapContinuationHooks(inner harness.HookRunner, initialUserPrompt, label string, maxNudges int) harness.HookRunner {
	return WrapChatContinuationHooks(inner, "", nil, initialUserPrompt, label, maxNudges)
}

func WrapChatContinuationHooks(inner harness.HookRunner, agentKey string, boundTools map[string]bool, initialUserPrompt, label string, maxNudges int) harness.HookRunner {
	if maxNudges <= 0 {
		maxNudges = 8
	}
	return &continuationHooks{
		inner:             inner,
		agentKey:          agentKey,
		boundTools:        boundTools,
		initialUserPrompt: initialUserPrompt,
		label:             label,
		maxNudges:         maxNudges,
	}
}

func isSoloTargetProbingTool(name string) bool {
	switch name {
	case "Bash", "run_security_tool", "WebFetch", "browser_inspect", "verify_xss_execution",
		"shell_open", "shell_send", "audit_frontend_api_surface", "verify_access_control_matrix",
		"verify_endpoint_idempotency":
		return true
	default:
		return false
	}
}

func (c *continuationHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if shouldAutoDelegateToTask(c.agentKey, c.boundTools, c.initialUserPrompt) && isSoloTargetProbingTool(name) {
		if c.taskDispatched.Load() {
			return true, "[Task Handoff Complete] You have already dispatched this engagement to BEHEMOTH's parallel Multi-Agent Tasks engine, where Planner and concurrent Workers are now executing it simultaneously. Do NOT run duplicate solo scans in Chat — immediately conclude your Chat turn with a clear summary, a clickable `[Task #<id>](/function/tasks/detail?id=<id>)` link, and inform the user that live finding & completion updates will appear automatically in this Chat!", nil
		}
		if c.soloProbeAttempts.Add(1) <= 3 {
			return true, "[Task Orchestration Guard] In default Auto Chat, target vulnerability scans and penetration tests MUST be converted into a parallel Multi-Agent Task instead of grinding sequentially in single-agent Chat. First call `list_tasks` (to avoid duplicate tasks for the same domain), optionally register scope via `add_company_scope` / `insert_assets`, pre-fill a comprehensive Task (`description` + structured `goal`), and dispatch it via `spawn_task` (or `add_task_hint` if an active task already exists for this target). Then reply to the user with the `[Task #<id>](/function/tasks/detail?id=<id>)` link!", nil
		}
	}
	if c.inner != nil {
		return c.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (c *continuationHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if !isErr && (name == "spawn_task" || name == "add_task_hint" || name == "set_task_goals") {
		c.taskDispatched.Store(true)
	}
	if c.inner != nil {
		c.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (c *continuationHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if c.inner != nil {
		prevent, blocking, msg := c.inner.Stop(ctx, messages)
		if prevent || len(blocking) > 0 {
			return prevent, blocking, msg
		}
	}
	shouldNudge, nudgeMsg := IsPrematureActionTurnForAgent(c.agentKey, c.boundTools, messages, c.initialUserPrompt)
	if !shouldNudge {
		return false, nil, ""
	}
	n := c.nudges.Add(1)
	if int(n) > c.maxNudges {
		log.Printf("[continuation %s] Premature stop reached max nudges (%d), allowing completion", c.label, c.maxNudges)
		return false, nil, ""
	}
	log.Printf("[continuation %s] Detected premature stop without tool call, injecting continuation nudge (%d/%d)", c.label, n, c.maxNudges)
	return false, []string{nudgeMsg}, ""
}

// WrapWorkerContinuationHooks ensures that autonomous task Workers never stop
// mid-intent after a status sentence ("Let me check..."), thinking-only turn, or
// tool error without completing their probing and recording results.
func WrapWorkerContinuationHooks(inner harness.HookRunner, intentID int64, workerName string, maxNudges int) harness.HookRunner {
	if maxNudges <= 0 {
		maxNudges = 6
	}
	return &workerContinuationHooks{
		inner:     inner,
		label:     fmt.Sprintf("%s-intent-%d", workerName, intentID),
		maxNudges: maxNudges,
	}
}

type workerContinuationHooks struct {
	inner     harness.HookRunner
	label     string
	nudges    atomic.Int64
	maxNudges int
}

func (w *workerContinuationHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if w.inner != nil {
		return w.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (w *workerContinuationHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if w.inner != nil {
		w.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (w *workerContinuationHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if w.inner != nil {
		prevent, blocking, msg := w.inner.Stop(ctx, messages)
		if prevent || len(blocking) > 0 {
			return prevent, blocking, msg
		}
	}
	var lastAsst *llm.Message
	lastAsstIdx := -1
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == llm.RoleAssistant {
			lastAsst = &messages[i]
			lastAsstIdx = i
			break
		}
	}
	if lastAsst == nil || len(lastAsst.ToolUses()) > 0 {
		return false, nil, ""
	}
	text := strings.TrimSpace(lastAsst.Text())
	var nudge string
	if text == "" {
		nudge = continuationThinkingNudge
	} else {
		prevWasToolError := false
		if lastAsstIdx > 0 {
			prev := messages[lastAsstIdx-1]
			if prev.Role == llm.RoleUser && len(prev.Content) > 0 {
				allErr, hasToolRes := true, false
				for _, b := range prev.Content {
					if b.Type == llm.BlockToolResult {
						hasToolRes = true
						if !b.IsError {
							allErr = false
						}
					}
				}
				if hasToolRes && allErr {
					prevWasToolError = true
				}
			}
		}
		if prevWasToolError && len(text) < 400 {
			nudge = continuationToolErrorNudge
		} else if len(text) <= 350 && !strings.Contains(text, "## ") && (reActionIntentAnnouncement.MatchString(text) || strings.HasSuffix(text, ":") || strings.HasSuffix(text, "...") || strings.HasSuffix(text, "…")) {
			nudge = continuationPrematureIntentNudge
		}
	}
	if nudge == "" {
		return false, nil, ""
	}
	n := w.nudges.Add(1)
	if int(n) > w.maxNudges {
		return false, nil, ""
	}
	log.Printf("[continuation %s] Worker premature stop detected, injecting continuation nudge (%d/%d)", w.label, n, w.maxNudges)
	return false, []string{nudge}, ""
}

// WrapPlannerContinuationHooks ensures the Planner does not exit prematurely after
// a thinking-only turn, a tool error, or an action announcement without calling
// its planning tools (add_intent, prove_goal, etc.).
func WrapPlannerContinuationHooks(inner harness.HookRunner, label string, maxNudges int) harness.HookRunner {
	if maxNudges <= 0 {
		maxNudges = 4
	}
	return &workerContinuationHooks{
		inner:     inner,
		label:     label,
		maxNudges: maxNudges,
	}
}
