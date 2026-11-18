package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedBySchedule = cause("paused_by_schedule", "Scheduled window ended; task paused",
		"The task will resume in the next scheduled window; this run has stopped")
	AbortPausedByProxy = cause("paused_by_proxy", "Global proxy error; task paused",
		"The global outbound proxy failed to connect and the task was paused; it will automatically resume once the proxy recovers")
	AbortPausedByUser = cause("paused_by_user", "User paused the task",
		"The user paused the task via the task control API (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was cancelled; running intents return to frontier(open) and restart from the beginning when resumed")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "Orchestrator Agent paused the task",
		"The orchestrator Agent called pause_task to pause this task. This Planner/Worker run was cancelled; running intents return to frontier(open) and restart when resumed")
	AbortTaskDeleted = cause("task_deleted", "Task deleted",
		"The task is being deleted (DELETE /api/tasks/{id}); the delete barrier cancelled active Planner, Worker, and Main Agent runs for this task, and results from this run are discarded")
	AbortPausedOnReload = cause("paused_on_reload", "Backend restored task paused state",
		"On startup, the backend restored the persisted paused state from the database. This run was cancelled; normally no Agents are running during startup recovery")
	AbortGoalMet = cause("goal_met", "Planner determined task goals met",
		"The Planner determined that task goals were met, marked the task done, and cancelled remaining Workers; those intents are marked stopped rather than failed")
	AbortNoResultStop = cause("no_result_stop", "No-result drain timeout expired",
		"The task reached the no-result checkpoint without meeting the finding count/severity threshold, and hard-cancelled after the 90s drain grace period; intents are marked exhausted and recorded facts/assets are preserved")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "Task timeout drain grace expired",
		"The task reached its timeout and waited 90s for active Workers to wrap up before hard-cancelling; intents are marked exhausted and facts/assets written during settlement are preserved")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "Planner terminated this intent",
		"The Planner called kill_work to terminate this intent (typically off-track or low value); the intent is marked stopped and will not be reclaimed automatically")
	AbortWorkPausedByUser = cause("work_paused_by_user", "User paused this Worker intent",
		"The user paused the running Worker. This run was cancelled and the intent moved to paused; recorded intents, facts, findings, and activity logs are preserved, and execution restarts when resumed")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "User deleted this Worker intent",
		"The user deleted the running Worker. This run was cancelled; once the Worker exits its write section, the server applies the chosen deletion mode — soft delete marks it deleted while keeping outputs, and hard delete cascades to downstream nodes supported solely by it")
	AbortWorkFinished = cause("work_finished", "Worker finished and released context",
		"The Worker finished normally and the engine released its context in detachWork. This is not an interruption; if it appears in an abort message, cancellation raced with completion")
	AbortPausedRaceGuard = cause("paused_race_guard", "New run rejected while task paused",
		"While the task is paused, the engine refuses to issue new execution contexts to prevent a race between claim and pause; claimed intents return to the frontier")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "User stopped this conversation turn",
		"The user clicked Stop to abort the current Main Agent or chat Agent turn. Recorded activity is preserved and you can send the next message")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "Task paused; Main Agent turn aborted",
		"When the user paused the task, the active Main Agent turn was cancelled as well. Recorded activity is preserved; resuming the task will not replay this message automatically")
	AbortChatTurnFinished = cause("chat_turn_finished", "Turn finished and released context",
		"The conversation turn finished normally and the server released its context resources. This is not an interruption; if it appears in an abort message, cancellation raced with completion")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "Backend process shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating, or shutting down. All active Agents are cancelled; any remaining running intents are reset to open on restart")
	AbortRunHardTimeout = cause("run_hard_timeout", "Per-run hard timeout triggered",
		"A single run exceeded both its soft wall-clock budget and grace period, indicating a model request or tool call hung without returning and prevented normal turn-boundary wrap-up. Inspect the last pending tool call before interruption")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "Upstream context deadline exceeded",
			"Upstream context reached its deadline without a named cause via WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "Canceled without named cause",
			"Upstream context was canceled without attaching a named cause via context.WithCancelCause; register the cause in agent/cancelcause.go", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
