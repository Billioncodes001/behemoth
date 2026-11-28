package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
	"github.com/Autumn-27/behemoth/intercept"
)

var taskChatSyncMu sync.Mutex

// conversationIDFromToolContext extracts the originating /chat conversation ID
// when a tool (such as spawn_task or add_task_hint) is invoked inside a chat turn.
func conversationIDFromToolContext(ctx context.Context) int64 {
	if ctx == nil {
		return 0
	}
	if cid := intercept.ConvIDFromContext(ctx); cid > 0 {
		return cid
	}
	sid := strings.TrimSpace(agent.RunInfoFrom(ctx).SessionID)
	if strings.HasPrefix(sid, "conv-") {
		if cid, err := strconv.ParseInt(strings.TrimPrefix(sid, "conv-"), 10, 64); err == nil && cid > 0 {
			return cid
		}
	}
	return 0
}

func (s *Server) activeWorkerConcurrencyForTask(t *Task) int {
	if s != nil && s.m != nil {
		if slots, err := workerSlotsForTask(t, s.m.WorkerPools(), s.m.Workers()); err == nil && len(slots) > 0 {
			return len(slots)
		}
		if n := workerCountForTask(t, s.m.Workers()); n > 0 {
			return n
		}
	}
	if t != nil && t.WorkerCount > 0 {
		return t.WorkerCount
	}
	return 3
}

// linkTaskToConversationFromCtx binds taskIDStr to the originating /chat conversation
// (if invoked from /chat) so live progress, finding, and completion updates stream
// back into that conversation.
func (s *Server) linkTaskToConversationFromCtx(ctx context.Context, taskIDStr string, existingTask bool) int64 {
	if s == nil || s.m == nil || s.m.pg == nil {
		return 0
	}
	convID := conversationIDFromToolContext(ctx)
	if convID <= 0 {
		return 0
	}
	taskID, err := strconv.ParseInt(strings.TrimSpace(taskIDStr), 10, 64)
	if err != nil || taskID <= 0 {
		return 0
	}
	agentKey := "auto"
	if conv, err := s.m.pg.GetConversation(convID); err == nil && conv != nil && strings.TrimSpace(conv.AgentKey) != "" {
		agentKey = conv.AgentKey
	}
	var baselineFindingID int64
	if existingTask {
		baselineFindingID, _ = s.m.pg.MaxFindingIDForTask(taskID)
	}
	if err := s.m.pg.UpsertTaskChatLink(taskID, convID, agentKey, baselineFindingID); err != nil {
		log.Printf("[task-chat] link task #%d <-> conv #%d failed: %v", taskID, convID, err)
		return 0
	}
	return convID
}

// pushTaskChatUpdate appends an uncollapsed Markdown update message into convID
// and broadcasts it immediately over the conversation's real-time SSE stream.
func (s *Server) pushTaskChatUpdate(convID int64, markdown string) {
	if s == nil || s.m == nil || s.m.pg == nil || convID <= 0 {
		return
	}
	md := strings.TrimSpace(markdown)
	if md == "" {
		return
	}
	conv, err := s.m.pg.GetConversation(convID)
	if err != nil || conv == nil {
		return
	}
	worker := strings.TrimSpace(conv.AgentKey)
	if worker == "" {
		worker = "auto"
	}
	rec := db.Activity{
		Worker:  worker,
		Kind:    "result",
		Summary: firstLine(md, 160),
		Detail:  md,
	}
	aid, err := s.m.pg.AppendConvActivity(convID, rec)
	if err != nil {
		log.Printf("[task-chat] append activity to conv #%d failed: %v", convID, err)
		return
	}
	rec.ID = aid
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	_ = s.m.pg.TouchConversation(convID)
	globalConvStreamHub.publish(convID, "activity", activityDTO(rec))
}

func taskDisplayLabel(t *Task) string {
	if t == nil {
		return "Task"
	}
	st := t.lifecycleSnapshot()
	title := strings.TrimSpace(st.Name)
	if title == "" {
		title = strings.TrimSpace(t.Description)
	}
	if title == "" {
		title = "Task #" + t.ID
	}
	return title
}

func formatCompactDurationSec(sec int64) string {
	if sec <= 0 {
		return "<1m"
	}
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	m := sec / 60
	remS := sec % 60
	if m < 60 {
		if remS == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, remS)
	}
	h := m / 60
	remM := m % 60
	return fmt.Sprintf("%dh %02dm", h, remM)
}

// notifyTaskGoalsReadyToChat posts an initial breakdown into any linked /chat
// conversation as soon as the Goal Decomposer finishes creating sub-goals and
// the parallel Worker pool starts executing.
func (s *Server) notifyTaskGoalsReadyToChat(t *Task, goals []goalSpec) {
	if s == nil || s.m == nil || s.m.pg == nil || t == nil || len(goals) == 0 {
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskID <= 0 {
		return
	}
	links, err := s.m.pg.ListTaskChatLinksByTask(taskID)
	if err != nil || len(links) == 0 {
		return
	}
	workers := s.activeWorkerConcurrencyForTask(t)
	var b strings.Builder
	fmt.Fprintf(&b, "### Multi-Agent Task Update · [Task #%s](/function/tasks/detail?id=%s)\n", t.ID, t.ID)
	fmt.Fprintf(&b, "**%s** has been decomposed into **%d parallel sub-goal(s)** and **%d simultaneous Worker agent(s)** (+ Planner & Reporter) are now executing:\n\n",
		taskDisplayLabel(t), len(goals), workers)
	maxShow := len(goals)
	if maxShow > 8 {
		maxShow = 8
	}
	for i := 0; i < maxShow; i++ {
		g := goals[i]
		if strings.TrimSpace(g.VulnClass) != "" {
			fmt.Fprintf(&b, "%d. **[%s]** %s\n", i+1, g.VulnClass, strings.TrimSpace(g.Text))
		} else {
			fmt.Fprintf(&b, "%d. %s\n", i+1, strings.TrimSpace(g.Text))
		}
	}
	if len(goals) > maxShow {
		fmt.Fprintf(&b, "- *...plus %d additional sub-goal(s)*\n", len(goals)-maxShow)
	}
	fmt.Fprintf(&b, "\nConfirmed vulnerabilities and the final wrap-up will appear automatically right here in Chat, or you can inspect live worker traces anytime in **[Task #%s](/function/tasks/detail?id=%s)**.", t.ID, t.ID)
	msg := b.String()

	for _, link := range links {
		won, err := s.m.pg.MarkTaskChatGoalsNotified(taskID, link.ConversationID)
		if err != nil || !won {
			continue
		}
		s.pushTaskChatUpdate(link.ConversationID, msg)
	}
}

func (s *Server) triggerTaskChatSyncAsync(taskIDStr string) {
	if s == nil {
		return
	}
	tid, err := strconv.ParseInt(strings.TrimSpace(taskIDStr), 10, 64)
	if err != nil || tid <= 0 {
		return
	}
	go s.syncSingleTaskChatUpdates(tid)
}

// ensureOpenGoalAndReviveTask guarantees that when a terminal or goalless task
// receives a new objective (e.g. from a Cooldown/Cron continuation wave or a
// follow-up prompt in /chat), at least one open Goal node exists on its
// ExplorationStore BEFORE reviveTask wakes plannerLoop — otherwise engine.go's
// `!t.Store.HasOpenGoal()` gate would immediately re-close the task as `done`
// without running the Planner.
func (s *Server) ensureOpenGoalAndReviveTask(t *Task, objectiveText string) {
	if s == nil || t == nil || t.Store == nil {
		return
	}
	open, err := t.Store.HasOpenGoal()
	if err == nil && !open {
		goalText := strings.TrimSpace(objectiveText)
		if goalText == "" {
			goalText = "Execute follow-up exploration and verification objective"
		}
		if len(goalText) > 800 {
			goalText = goalText[:800] + "..."
		}
		if gid, gerr := t.Store.AddGoal(map[string]any{"text": goalText}, "human"); gerr == nil && gid > 0 {
			if of, _ := t.Store.OriginFactID(); of > 0 {
				_ = t.Store.Link(of, db.RelSpawns, gid)
			}
			t.NotifyGoal([]string{goalText})
		}
	}
	s.reviveTask(t)
}

func (s *Server) syncSingleTaskChatUpdates(taskID int64) {
	if s == nil || s.m == nil || s.m.pg == nil || taskID <= 0 {
		return
	}
	// Mirror any files this Task wrote under `tasks/<id>/domains/...` into the
	// unified `domains/<root-domain>/` folder whenever a Task finishes/updates.
	if s.m != nil {
		if t, ok := s.m.Task(strconv.FormatInt(taskID, 10)); ok && t != nil {
			dom := extractPrimaryTargetDomain(t.Name + " " + t.Description + " " + t.Goal)
			s.syncTaskDomainsToWorkspace(t.ID, dom)
		}
	}
	s.syncBountyTrackerFromTaskFindings(taskID)

	taskChatSyncMu.Lock()
	defer taskChatSyncMu.Unlock()

	links, err := s.m.pg.ListTaskChatLinksByTask(taskID)
	if err != nil || len(links) == 0 {
		return
	}
	s.processTaskChatLinksLocked(links)
}

// syncTaskChatUpdates sweeps all linked Task <-> Chat pairs (plus active Bounty
// Tracker tasks) so newly recorded findings, proxy blockers, and terminal
// completions are reliably delivered across the platform.
func (s *Server) syncTaskChatUpdates() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	s.syncAllBountyTrackersFromFindings()

	taskChatSyncMu.Lock()
	defer taskChatSyncMu.Unlock()

	links, err := s.m.pg.ListTaskChatLinks()
	if err != nil || len(links) == 0 {
		return
	}
	s.processTaskChatLinksLocked(links)
}

func (s *Server) processTaskChatLinksLocked(links []db.TaskChatLink) {
	// Group links by task_id so we query each task's state/findings once.
	byTask := make(map[int64][]db.TaskChatLink)
	for _, l := range links {
		byTask[l.TaskID] = append(byTask[l.TaskID], l)
	}
	var metrics map[int64]db.TaskListMetrics
	for taskID, taskLinks := range byTask {
		taskIDStr := strconv.FormatInt(taskID, 10)
		t, ok := s.m.Task(taskIDStr)
		if !ok || t == nil {
			continue
		}
		lifecycle := t.lifecycleSnapshot()
		status := s.resolvedTaskStatusFromSnapshot(t, lifecycle)

		// 1. Stream any newly discovered findings since each conversation's watermark.
		for _, link := range taskLinks {
			newFindings, err := s.m.pg.ListTaskFindingsAfter(taskID, link.LastFindingID)
			if err != nil || len(newFindings) == 0 {
				continue
			}
			maxID := link.LastFindingID
			for _, f := range newFindings {
				if f.ID > maxID {
					maxID = f.ID
				}
				sev := strings.ToUpper(strings.TrimSpace(f.Severity))
				if sev == "" {
					sev = "MEDIUM"
				}
				title := strings.TrimSpace(f.Name)
				if title == "" {
					title = strings.TrimSpace(f.VulnClass)
				}
				if title == "" {
					title = fmt.Sprintf("Finding #%d", f.ID)
				}
				var fb strings.Builder
				fmt.Fprintf(&fb, "### Vulnerability Discovered · [Task #%s](/function/tasks/detail?id=%s)\n", t.ID, t.ID)
				fmt.Fprintf(&fb, "- **Finding**: **[%s]** %s *(ID `#%d`)*\n", sev, title, f.ID)
				if strings.TrimSpace(f.VulnClass) != "" && !strings.EqualFold(strings.TrimSpace(f.VulnClass), title) {
					fmt.Fprintf(&fb, "- **Category**: `%s`\n", strings.TrimSpace(f.VulnClass))
				}
				if strings.TrimSpace(f.Worker) != "" {
					fmt.Fprintf(&fb, "- **Discovered By**: `%s`\n", strings.TrimSpace(f.Worker))
				}
				if sum := strings.TrimSpace(f.Summary); sum != "" {
					fmt.Fprintf(&fb, "- **Summary**: %s\n", sum)
				}
				fmt.Fprintf(&fb, "\n[View Vulnerability Findings](/function/findings) · [Open Live Task #%s](/function/tasks/detail?id=%s)", t.ID, t.ID)
				s.pushTaskChatUpdate(link.ConversationID, fb.String())
			}
			_ = s.m.pg.AdvanceTaskChatFindingWatermark(taskID, link.ConversationID, maxID)
		}

		// 2. Notify on proxy fail-closed pause or terminal completion (done / timeout / failed).
		notifyKey := ""
		switch {
		case isTerminalStatus(status):
			notifyKey = status
		case status == "paused" && lifecycle.PauseReason == "paused_by_proxy":
			notifyKey = "paused_by_proxy"
		}
		if notifyKey == "" {
			continue
		}

		if metrics == nil {
			metrics, _ = s.m.PG().TaskListMetricsAll()
		}
		metric := metrics[t.ExpID]
		allFindings, _ := s.m.pg.ListTaskFindingsAfter(taskID, 0)

		for _, link := range taskLinks {
			if link.LastStatusNotified == notifyKey {
				continue
			}
			won, err := s.m.pg.MarkTaskChatStatusNotified(taskID, link.ConversationID, notifyKey)
			if err != nil || !won {
				continue
			}
			if notifyKey == "paused_by_proxy" {
				msg := fmt.Sprintf(
					"### Action Needed · [Task #%s](/function/tasks/detail?id=%s) Paused on Proxy Guard\n"+
						"**%s** paused automatically to protect your server IP because all active proxies in Proxy Pool failed or ran out of bandwidth.\n\n"+
						"- Refresh/import working proxies or enable Tor in **[Proxy Pool](/system/proxy)**, then resume **[Task #%s](/function/tasks/detail?id=%s)** (or reply here in Chat after updating proxies).",
					t.ID, t.ID, taskDisplayLabel(t), t.ID, t.ID,
				)
				s.pushTaskChatUpdate(link.ConversationID, msg)
				continue
			}

			// Terminal wrap-up summary (done / timeout / failed)
			runSec := taskRunSeconds(lifecycle.ActiveRunSeconds, lifecycle.RunSegmentStartedAt, time.Now().Unix(), status, lifecycle.Paused, lifecycle.Queued)
			statusHeading := "Completed"
			switch status {
			case "timeout":
				if lifecycle.StopReason == "no_result" {
					statusHeading = "Stopped (No-Result Stop-Loss Reached)"
				} else {
					statusHeading = "Completed (Time Budget Wrap-Up)"
				}
			case "failed":
				statusHeading = "Stopped with Error"
			}

			crit, high, med, low := 0, 0, 0, 0
			for _, f := range allFindings {
				switch strings.ToLower(strings.TrimSpace(f.Severity)) {
				case "critical":
					crit++
				case "high":
					high++
				case "medium":
					med++
				default:
					low++
				}
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "### Multi-Agent Task %s · [Task #%s](/function/tasks/detail?id=%s)\n", statusHeading, t.ID, t.ID)
			fmt.Fprintf(&sb, "- **Assignment**: %s\n", taskDisplayLabel(t))
			fmt.Fprintf(&sb, "- **Active Parallel Runtime**: `%s` · **Sub-Goals Met**: `%d/%d`\n",
				formatCompactDurationSec(runSec), metric.Goals.Met, metric.Goals.Total)
			fmt.Fprintf(&sb, "- **Findings Recorded**: **%d total** (`%d Critical` · `%d High` · `%d Medium` · `%d Low`)\n",
				len(allFindings), crit, high, med, low)

			if len(allFindings) > 0 {
				sb.WriteString("\n**Confirmed & Recorded Findings:**\n")
				limit := len(allFindings)
				if limit > 12 {
					limit = 12
				}
				for i := 0; i < limit; i++ {
					f := allFindings[i]
					sev := strings.ToUpper(strings.TrimSpace(f.Severity))
					if sev == "" {
						sev = "MEDIUM"
					}
					title := strings.TrimSpace(f.Name)
					if title == "" {
						title = strings.TrimSpace(f.VulnClass)
					}
					fmt.Fprintf(&sb, "%d. **[%s]** %s *(Finding `#%d`)*\n", i+1, sev, title, f.ID)
				}
				if len(allFindings) > limit {
					fmt.Fprintf(&sb, "- *...plus %d more finding(s)*\n", len(allFindings)-limit)
				}
			} else {
				sb.WriteString("\nNo confirmed exploitable vulnerabilities met the verification threshold during this run.\n")
			}

			fmt.Fprintf(&sb, "\n[Open Full Task #%s Graph & Worker Traces](/function/tasks/detail?id=%s) · [Open Vulnerability Findings & Reports](/function/findings)\n", t.ID, t.ID)
			sb.WriteString("*Reply right here in Chat if you want to steer follow-up exploitation, expand scope, or ask questions about any finding.*")
			s.pushTaskChatUpdate(link.ConversationID, sb.String())
		}
	}
}

// conversationLinkedTasksContext builds a compact live status note for any Tasks
// linked to convID so follow-up messages in /chat immediately know the exact
// Task IDs, current run states, and findings counts without extra lookups.
func (s *Server) conversationLinkedTasksContext(convID int64) string {
	if s == nil || s.m == nil || s.m.pg == nil || convID <= 0 {
		return ""
	}
	links, err := s.m.pg.ListTaskChatLinksByConversation(convID)
	if err != nil || len(links) == 0 {
		return ""
	}
	var lines []string
	maxTasks := len(links)
	if maxTasks > 5 {
		maxTasks = 5
	}
	for i := 0; i < maxTasks; i++ {
		tidStr := strconv.FormatInt(links[i].TaskID, 10)
		t, ok := s.m.Task(tidStr)
		if !ok || t == nil {
			continue
		}
		st := s.resolvedTaskStatus(t)
		findings, _ := s.m.pg.ListTaskFindingsAfter(links[i].TaskID, 0)
		lines = append(lines, fmt.Sprintf("- Task #%s (%s): status=%s, recorded_findings=%d, url=/function/tasks/detail?id=%s",
			t.ID, taskDisplayLabel(t), st, len(findings), t.ID))
	}
	if len(lines) == 0 {
		return ""
	}
	return "\n\n<system-reminder>\n[Linked Multi-Agent Tasks for This Chat Conversation]\n" +
		strings.Join(lines, "\n") +
		"\nIf the user is asking for progress, steering a running scan, or requesting follow-up testing on the same target, inspect/steer this linked Task (via get_task_graph / list_task_findings / add_task_hint) rather than starting a duplicate Task or running a slow solo scan in Chat.\n</system-reminder>"
}
