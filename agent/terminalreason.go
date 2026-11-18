package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/norma/harness"
)

// runTrace retains the latest tool call so an interrupted run can identify the
// operation that was still in flight.
type runTrace struct {
	startedAt time.Time
	id        string
	name      string
	input     string
	at        time.Time
	pending   bool
}

func (t *runTrace) start(id, name, input string) {
	t.id, t.name, t.input, t.at, t.pending = id, name, input, time.Now(), true
}

func (t *runTrace) done(id string) {
	if id == t.id {
		t.pending = false
	}
}

var reasonHint = map[harness.TerminalReason]string{
	harness.ReasonCompleted:         "The model finished the turn normally without a prose summary; facts and assets follow this turn's tool call history",
	harness.ReasonMaxTurns:          "Reached step budget (MaxTurns): SDK executed wrap-up and persisted facts/assets; intent marked exhausted so the Planner can pivot rather than treating it as a failure",
	harness.ReasonTimeout:           "Reached per-run wall-clock budget (MaxDuration): interrupted in-flight tools and entered wrap-up to persist identified facts/assets; intent marked exhausted",
	harness.ReasonModelError:        "Model or API call failed (network, auth, rate limit, provider 5xx, etc.); after retries exhausted, intent marked blocked — inspect execution via get_worker_trace before re-dispatching",
	harness.ReasonBlockingLimit:     "Context length hit the hard limit and the request was blocked before sending; narrow intent scope or compress tool outputs",
	harness.ReasonPromptTooLong:     "Prompt is too long and context compaction retries were exhausted; cannot continue",
	harness.ReasonImageError:        "Current model does not support multimodal input in this turn; switch to a vision-capable model or avoid returning images from tools",
	harness.ReasonStopHookPrevented: "Stop hook prevented turn completion and execution could not continue; check whether task Guard rules are overly strict",
	harness.ReasonHookStopped:       "A tool or hook stopped execution (e.g. out-of-scope target or blocked command); inspect the last tool_result interception message",
	harness.ReasonAbortedStreaming:  "Run was cancelled during streaming model output",
	harness.ReasonAbortedTools:      "Run was cancelled during tool execution",
}

// terminalText renders a terminal event with no final text into a compact summary
// and a Markdown detail block.
func terminalText(ctx context.Context, term *harness.Terminal, tr *runTrace) (string, string) {
	reason := term.Reason
	aborted := reason == harness.ReasonAbortedStreaming || reason == harness.ReasonAbortedTools
	if reason == "" && ctx.Err() != nil {
		aborted = true
	}

	var sum string
	if aborted {
		_, short, _, ok := AbortReason(ctx)
		if !ok {
			short = "Cancellation cause unavailable"
		}
		stage := "execution"
		switch reason {
		case harness.ReasonAbortedStreaming:
			stage = "model output stage"
		case harness.ReasonAbortedTools:
			stage = "tool execution stage"
		}
		sum = "(Run interrupted: " + short + "; stopped during " + stage + progressSuffix(term, tr) + ", incomplete)"
	} else if reason == harness.ReasonMaxTurns || reason == harness.ReasonTimeout {
		sum = "(Reached run budget limit (" + string(reason) + "), wrapped up and persisted facts" + progressSuffix(term, tr) + "; no prose summary)"
	} else {
		hint := terminalReasonHint(reason)
		sum = "(No prose summary, terminal state " + terminalReasonLabel(reason) + ": " + firstLine(hint, 80) + ")"
	}

	var b strings.Builder
	b.WriteString(sum)
	b.WriteString("\n\n")
	displayReason := terminalReasonLabel(reason)
	fmt.Fprintf(&b, "- **Terminal State**: `%s` - %s\n", displayReason, terminalReasonHint(reason))
	if aborted {
		code, _, why, ok := AbortReason(ctx)
		if ok {
			fmt.Fprintf(&b, "- **Interruption Cause** (`%s`): %s\n", code, why)
		} else {
			b.WriteString("- **Interruption Cause**: Unavailable; caller may not have attached a named cause via context.WithCancelCause\n")
		}
	}
	if term.Err != nil {
		fmt.Fprintf(&b, "- **Underlying Error**: `%v`\n", term.Err)
	}
	if aborted && strings.TrimSpace(term.Text) != "" {
		b.WriteString("- **Partial Output Before Cancellation**:\n\n")
		b.WriteString(term.Text)
		b.WriteString("\n\n")
	}
	if term.Turns > 0 {
		fmt.Fprintf(&b, "- **Executed**: %d model turns\n", term.Turns)
	}
	if !tr.startedAt.IsZero() {
		fmt.Fprintf(&b, "- **Run Duration**: %s\n", roundDur(time.Since(tr.startedAt)))
	}
	if u := term.Usage; u.InputTokens+u.OutputTokens+u.CacheReadTokens+u.CacheWriteTokens > 0 {
		fmt.Fprintf(&b, "- **Cumulative Tokens**: input %d / output %d / cache read %d / cache write %d\n",
			u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
	}
	if tr.name == "" {
		b.WriteString("- **Tool Calls**: Ended before any tool call was issued\n")
	} else if tr.pending {
		fmt.Fprintf(&b, "- **Tool In Flight When Interrupted**: `%s` (ran for %s, **no result returned**)\n\n  ```json\n  %s\n  ```\n",
			tr.name, roundDur(time.Since(tr.at)), firstLine(tr.input, 300))
	} else {
		fmt.Fprintf(&b, "- **Last Tool Before Interruption**: `%s` (returned normally)\n", tr.name)
	}
	return sum, b.String()
}

func terminalReasonLabel(reason harness.TerminalReason) string {
	if reason == "" {
		return "context_canceled"
	}
	return string(reason)
}

func terminalReasonHint(reason harness.TerminalReason) string {
	if hint := reasonHint[reason]; hint != "" {
		return hint
	}
	if reason == "" {
		return "Run context was canceled without emitting a Terminal event"
	}
	return "Unknown terminal state; harness may have added a new TerminalReason — update reasonHint"
}

func progressSuffix(term *harness.Terminal, tr *runTrace) string {
	var parts []string
	if term.Turns > 0 {
		parts = append(parts, fmt.Sprintf("%d turns", term.Turns))
	}
	if !tr.startedAt.IsZero() {
		parts = append(parts, roundDur(time.Since(tr.startedAt)))
	}
	if len(parts) == 0 {
		return ""
	}
	return ", ran " + strings.Join(parts, " / ")
}

func roundDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	default:
		return d.Round(time.Minute).String()
	}
}
