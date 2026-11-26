package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/intercept"
)

func TestChatSpawnTaskLinksAndStreamsLiveUpdatesBackToChat(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)

	conv, err := s.m.pg.CreateConversation("auto", "portal.example.com", nil)
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}

	// Subscribe to the conversation's live SSE hub BEFORE updates fire to prove
	// an idle /chat tab receives Task progress & finding updates in real time!
	sseCh, unsub := globalConvStreamHub.subscribe(conv.ID)
	defer unsub()

	ctx := intercept.WithConvID(context.Background(), conv.ID)
	ctx = agent.WithRunInfo(ctx, agent.RunInfo{SessionID: "conv-" + strconv.FormatInt(conv.ID, 10)})

	spawnTool := s.toolSpawnTask()
	inJSON, _ := json.Marshal(map[string]any{
		"description": "Security Assessment · portal.example.com",
		"goal":        "Map attack surface, discover SQLi/XSS/IDOR vulnerabilities on https://portal.example.com, and verify working PoCs.",
	})
	res, err := spawnTool.Call(ctx, inJSON, nil)
	if err != nil || res.IsError {
		t.Fatalf("spawn_task failed: err=%v res=%s", err, res.Flatten())
	}
	flat := res.Flatten()
	if !strings.Contains(flat, "task created:") || !strings.Contains(flat, "/function/tasks/detail?id=") || !strings.Contains(flat, "live_chat_updates: linked to Conversation") {
		t.Fatalf("expected task_url and live_chat_updates in spawn_task result, got:\n%s", flat)
	}

	links, err := s.m.pg.ListTaskChatLinksByConversation(conv.ID)
	if err != nil || len(links) != 1 {
		t.Fatalf("expected 1 task_chat_links row, got len=%d err=%v", len(links), err)
	}
	taskID := links[0].TaskID
	taskIDStr := strconv.FormatInt(taskID, 10)
	task, ok := s.m.Task(taskIDStr)
	if !ok || task == nil {
		t.Fatalf("expected task %s in manager", taskIDStr)
	}

	// 1. Sub-goals decomposed -> posts Multi-Agent Task Update into /chat (once, idempotent)
	s.notifyTaskGoalsReadyToChat(task, []goalSpec{
		{VulnClass: "Recon", Text: "Enumerate subdomains, ports, and API surface of portal.example.com"},
		{VulnClass: "SQLi", Text: "Test authenticated and public parameters for SQL injection"},
	})
	s.notifyTaskGoalsReadyToChat(task, []goalSpec{
		{VulnClass: "Recon", Text: "Duplicate call must be ignored"},
	})

	// 2. Worker records a confirmed vulnerability finding -> streams into /chat
	fid, err := s.m.pg.AddFinding(taskID, 0, "SQL Injection", "Error-Based SQLi in /api/v1/invoices", "high",
		"Parameter `sort` allows database extraction via boolean/error differential.", "sqlmap PoC verified", "worker-2", nil)
	if err != nil || fid <= 0 {
		t.Fatalf("AddFinding failed: %v", err)
	}
	s.syncTaskChatUpdates()

	// 3. Task finishes ("done") -> posts executive completion wrap-up into /chat (once, idempotent)
	if err := s.m.SetTaskStatus(taskIDStr, "done"); err != nil {
		t.Fatalf("SetTaskStatus done: %v", err)
	}
	s.syncTaskChatUpdates()
	s.syncTaskChatUpdates() // second sweep must not duplicate any message

	msgs, _, err := s.m.pg.ConvActivityList(conv.ID, 0, 50)
	if err != nil {
		t.Fatalf("ConvActivityList: %v", err)
	}
	if len(msgs) != 3 {
		var summaries []string
		for _, m := range msgs {
			summaries = append(summaries, m.Summary)
		}
		t.Fatalf("expected exactly 3 Task->Chat updates (goals, finding, completion), got %d: %v", len(msgs), summaries)
	}
	d0, _ := s.m.pg.ConvActivityDetail(conv.ID, msgs[0].ID)
	d1, _ := s.m.pg.ConvActivityDetail(conv.ID, msgs[1].ID)
	d2, _ := s.m.pg.ConvActivityDetail(conv.ID, msgs[2].ID)
	if !strings.Contains(d0, "decomposed into **2 parallel sub-goal(s)**") {
		t.Fatalf("unexpected goals update:\n%s", d0)
	}
	if !strings.Contains(d1, "Error-Based SQLi in /api/v1/invoices") || !strings.Contains(d1, "[HIGH]") {
		t.Fatalf("unexpected finding update:\n%s", d1)
	}
	if !strings.Contains(d2, "Multi-Agent Task Completed") || !strings.Contains(d2, "1 High") {
		t.Fatalf("unexpected completion update:\n%s", d2)
	}

	// Verify real-time SSE frames arrived on the subscribed /chat stream!
	sseCount := 0
drainSSE:
	for {
		select {
		case frame := <-sseCh:
			if frame.Event == "activity" {
				sseCount++
			}
		case <-time.After(50 * time.Millisecond):
			break drainSSE
		}
	}
	if sseCount < 3 {
		t.Fatalf("expected at least 3 live SSE activity frames on idle /chat stream, got %d", sseCount)
	}

	// Verify dynamic system context exposes linked Task to follow-up Chat turns!
	ctxNote := s.conversationLinkedTasksContext(conv.ID)
	if !strings.Contains(ctxNote, "Task #"+taskIDStr) || !strings.Contains(ctxNote, "recorded_findings=1") {
		t.Fatalf("expected linked task note to include Task #%s and findings=1, got:\n%s", taskIDStr, ctxNote)
	}
}
