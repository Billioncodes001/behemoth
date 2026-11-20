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
	reActionIntentAnnouncement = regexp.MustCompile(`(?i)(?:^|[.!?]\s+|\n\s*)(?:let\s+me\b|let's\b|i\s+will\b|i'll\b|i\s+am\s+going\s+to\b|i'm\s+going\s+to\b|going\s+to\b|starting\s+(?:a\s+|the\s+)?(?:scan|recon|test|probe|check|investigation|analysis|enumeration)|running\s+(?:a\s+|the\s+)?(?:scan|recon|test|probe|check|command|tool)|checking\s+(?:the\s+)?(?:current\s+status|target|site|web|http|headers|ports|endpoints|vulnerabilities)|investigating\s+the\b|scanning\s+the\b|probing\s+the\b|now\s+let\s+me\b|next,?\s+let\s+me\b|next,?\s+i\s+will\b|first,?\s+let\s+me\b|allow\s+me\b)`)
	reActiveTaskPrompt         = regexp.MustCompile(`(?i)\b(scan|pentest|penetration\s+test|exploit|vulnerabilit(?:y|ies)|recon|reconnaissance|enumerate|probe|audit|assess|find\s+something|use\s+.*tools|check\s+.*for\s+vulnerabilit|attack|fuzz|crawl|spider|discover)\b`)
	reTargetHostOrURL          = regexp.MustCompile(`(?i)(?:https?://[^\s/$.?#].[^\s]*|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,24}\b)`)
	reReadOnlyQuestionPrompt   = regexp.MustCompile(`(?is)^\s*(?:\[manual\s+report|manual\s+selection\s+review|where\s+is\b|where\s+are\b|what\s+is\b|what\s+are\b|what\s+vulnerabilit|why\s+did\b|why\s+is\b|how\s+does\b|explain\b|summarize\b|show\s+me\s+(?:the\s+)?report\b)`)
)

const (
	continuationThinkingNudge = "[System Continuation] Your previous turn only produced internal thinking with no visible response and no tool call. Immediately execute your next step by calling the appropriate tool, or provide your final conclusion if all work is complete."

	continuationToolErrorNudge = "[System Continuation] The previous tool call returned an error and you responded with a brief status message without invoking any tool. Do not stop—immediately invoke the corrected tool call or use an alternative tool (e.g., Bash, Skill, WebFetch, insert_assets, spawn_task, report_finding) to continue the operation."

	continuationPrematureIntentNudge = "[System Continuation] You announced an action or next step in text without emitting a tool call. Never stop after a status announcement—immediately invoke the required tool (e.g., Bash, Skill, WebFetch, insert_assets, spawn_task, report_finding) and continue executing step-by-step until the user's request is thoroughly completed."

	continuationNoExecToolsNudge = "[System Continuation — Mandatory Live Execution] You have NOT executed any live reconnaissance or probing tools (such as Bash, WebFetch, or spawn_task) against the target yet—only meta/lookup tools were called. Never fabricate or guess scan results, IPs, headers, or asset IDs! Immediately invoke Bash (e.g., curl, dig, whatweb, nmap, nuclei, ffuf, python3) to perform live testing against the target."

	continuationIncompleteScanNudge = "[System Continuation — Incomplete Vulnerability Assessment] You have only executed %d live probing round(s) so far. The user requested a thorough vulnerability scan using the necessary tools. Do NOT stop early—continue your investigation now by: (1) inspecting the fetched HTML/JS source, links, forms, robots.txt, sitemap.xml, API endpoints, and HTTP security/CORS headers via Bash; (2) actively probing discovered endpoints and parameters for vulnerabilities (XSS, SQLi, SSRF, LFI, open redirects, exposed configs/.git/.env); and (3) registering discovered target assets via insert_assets."

	continuationMissingAssetSyncNudge = "[System Continuation — Mandatory Asset Synchronization] Before concluding your assessment, you must call insert_assets to persist the genuinely discovered target domain, IP address(es), open ports, and web services into the ARTEX Assets database (and call report_finding if any real vulnerability was verified). Invoke insert_assets now, then provide your final comprehensive report."
)

func IsPrematureActionTurn(messages []llm.Message, initialUserPrompt string) (bool, string) {
	return IsPrematureActionTurnForAgent("", nil, messages, initialUserPrompt)
}

func isActiveProbingAgent(agentKey string) bool {
	if agentKey == "" {
		return true // preserve legacy callers & unit tests that omit agentKey
	}
	switch strings.ToLower(strings.TrimSpace(agentKey)) {
	case "reporter", "asset_mapper", "goals", "credential_processor", "retester", "patch_watch", "planner":
		return false
	default:
		return true
	}
}

func isLiveTargetScanPrompt(agentKey, prompt string) bool {
	if !isActiveProbingAgent(agentKey) {
		return false
	}
	trimmed := strings.TrimSpace(prompt)
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

	execTurns, calledAssetOrTaskSync, completedReportingGoal := analyzeRunToolProgressDetailed(messages)
	if strings.EqualFold(strings.TrimSpace(agentKey), "reporter") && completedReportingGoal {
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

	// For active scan / assessment / tool-execution prompts on probing agents, verify that
	// real probing tools (Bash, WebFetch, spawn_task, etc.) and asset synchronization were
	// actually run — while NEVER hijacking reporter/read-only agents or unbound tools.
	if isLiveTargetScanPrompt(agentKey, initialUserPrompt) {
		if execTurns == 0 {
			return true, continuationNoExecToolsNudge
		}
		if execTurns < 3 {
			return true, fmt.Sprintf(continuationIncompleteScanNudge, execTurns)
		}
		canSyncAssets := boundTools == nil || boundTools["insert_assets"] || boundTools["add_company_scope"] || boundTools["spawn_task"] || boundTools["report_finding"]
		if !calledAssetOrTaskSync && canSyncAssets {
			return true, continuationMissingAssetSyncNudge
		}
	}
	return false, ""
}

// analyzeRunToolProgress scans messages since the last plain user prompt and counts:
// - execTurns: assistant turns that invoked substantive execution tools (Bash, WebFetch, web_search, spawn_task, ExecuteExtraTool, shell_open)
// - calledAssetOrTaskSync: whether insert_assets, add_company_scope, spawn_task, or report_finding was invoked
func analyzeRunToolProgress(messages []llm.Message) (execTurns int, calledAssetOrTaskSync bool) {
	execTurns, calledAssetOrTaskSync, _ = analyzeRunToolProgressDetailed(messages)
	return execTurns, calledAssetOrTaskSync
}

func analyzeRunToolProgressDetailed(messages []llm.Message) (execTurns int, calledAssetOrTaskSync bool, completedReportingGoal bool) {
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role == llm.RoleAssistant {
			uses := m.ToolUses()
			turnHadExec := false
			for _, u := range uses {
				switch u.Name {
				case "Bash", "WebFetch", "web_search", "spawn_task", "ExecuteExtraTool", "shell_open", "shell_send",
					"run_security_tool", "browser_inspect", "detect_deception_and_honeypot", "multi_engine_search", "exploit_search",
					"import_and_test_proxies", "manage_proxy_pool", "match_vuln_targets", "update_exploit_target_status",
					"check_patch_feeds", "add_patch_watch_feed", "discover_affected_sites_for_notification",
					"generate_vuln_exploit", "generate_payload", "search_ios_exploits":
					turnHadExec = true
				}
				switch u.Name {
				case "insert_assets", "add_company_scope", "spawn_task", "report_finding",
					"generate_vuln_exploit", "generate_payload":
					calledAssetOrTaskSync = true
				}
				switch u.Name {
				case "update_finding_report", "update_finding_case_report", "complete_finding_case_review", "complete_finding_retest":
					// Check that the corresponding tool result did not fail
					if !toolCallFailedInNextTurn(messages, i, u.ID) {
						completedReportingGoal = true
					}
				}
			}
			if turnHadExec {
				execTurns++
			}
		}
		if m.Role == llm.RoleUser {
			hasPlainText, hasToolResult := false, false
			for _, b := range m.Content {
				if b.Type == llm.BlockText && strings.TrimSpace(b.Text) != "" &&
					!strings.HasPrefix(strings.TrimSpace(b.Text), "<system-reminder>") &&
					!strings.HasPrefix(strings.TrimSpace(b.Text), "[System Continuation") {
					hasPlainText = true
				}
				if b.Type == llm.BlockToolResult {
					hasToolResult = true
				}
			}
			if hasPlainText && !hasToolResult {
				break
			}
		}
	}
	return execTurns, calledAssetOrTaskSync, completedReportingGoal
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

func (c *continuationHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if c.inner != nil {
		return c.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (c *continuationHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
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
