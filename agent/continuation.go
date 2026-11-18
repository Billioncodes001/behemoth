package agent

import (
	"context"
	"log"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

var (
	reActionIntentAnnouncement = regexp.MustCompile(`(?i)(?:^|[.!?]\s+|\n\s*)(?:let\s+me\b|let's\b|i\s+will\b|i'll\b|i\s+am\s+going\s+to\b|i'm\s+going\s+to\b|going\s+to\b|starting\s+(?:a\s+|the\s+)?(?:scan|recon|test|probe|check|investigation|analysis|enumeration)|running\s+(?:a\s+|the\s+)?(?:scan|recon|test|probe|check|command|tool)|checking\s+(?:the\s+)?(?:current\s+status|target|site|web|http|headers|ports|endpoints|vulnerabilities)|investigating\s+the\b|scanning\s+the\b|probing\s+the\b|now\s+let\s+me\b|next,?\s+let\s+me\b|next,?\s+i\s+will\b|first,?\s+let\s+me\b|allow\s+me\s+to\b)`)
	reActiveTaskPrompt         = regexp.MustCompile(`(?i)\b(scan|pentest|penetration\s+test|exploit|vulnerabilit(?:y|ies)|recon|reconnaissance|enumerate|probe|audit|assess|find\s+something|use\s+.*tools|check\s+.*for\s+vulnerabilit|attack|fuzz|crawl|spider|discover)\b`)
)

const (
	continuationThinkingNudge = "[System Continuation] Your previous turn only produced internal thinking with no visible response and no tool call. Immediately execute your next step by calling the appropriate tool, or provide your final conclusion if all work is complete."

	continuationToolErrorNudge = "[System Continuation] The previous tool call returned an error and you responded with a brief status message without invoking any tool. Do not stop—immediately invoke the corrected tool call or use an alternative tool (e.g., Bash, Skill, WebFetch, insert_assets, spawn_task, report_finding) to continue the operation."

	continuationPrematureIntentNudge = "[System Continuation] You announced an action or next step in text without emitting a tool call. Never stop after a status announcement—immediately invoke the required tool (e.g., Bash, Skill, WebFetch, insert_assets, spawn_task, report_finding) and continue executing step-by-step until the user's request is thoroughly completed."
)

func IsPrematureActionTurn(messages []llm.Message, initialUserPrompt string) (bool, string) {
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
	if text == "" {
		return true, continuationThinkingNudge
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

	if prevWasToolError && len(text) < 500 {
		return true, continuationToolErrorNudge
	}

	hasFinalReportHeadings := strings.Contains(text, "## ") || strings.Contains(text, "### ") || len(text) > 600
	if !hasFinalReportHeadings && len(text) <= 450 {
		if reActionIntentAnnouncement.MatchString(text) || strings.HasSuffix(text, ":") || strings.HasSuffix(text, "...") || strings.HasSuffix(text, "…") {
			return true, continuationPrematureIntentNudge
		}
		if reActiveTaskPrompt.MatchString(initialUserPrompt) && len(text) < 220 && countToolTurnsSinceLastUserText(messages) < 2 {
			return true, continuationPrematureIntentNudge
		}
	}
	return false, ""
}

func countToolTurnsSinceLastUserText(messages []llm.Message) int {
	turns := 0
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role == llm.RoleAssistant && len(m.ToolUses()) > 0 {
			turns++
		}
		if m.Role == llm.RoleUser {
			hasPlainText, hasToolResult := false, false
			for _, b := range m.Content {
				if b.Type == llm.BlockText && strings.TrimSpace(b.Text) != "" {
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
	return turns
}

type continuationHooks struct {
	inner             harness.HookRunner
	initialUserPrompt string
	label             string
	nudges            atomic.Int64
	maxNudges         int
}

func WrapContinuationHooks(inner harness.HookRunner, initialUserPrompt, label string, maxNudges int) harness.HookRunner {
	if maxNudges <= 0 {
		maxNudges = 8
	}
	return &continuationHooks{
		inner:             inner,
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
	shouldNudge, nudgeMsg := IsPrematureActionTurn(messages, c.initialUserPrompt)
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
