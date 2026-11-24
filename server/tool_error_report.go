package server

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/behemoth/db"
)

// tool_error_report.go — automatic tool-error → Agent Requests capture.
//
// Agents used to surface tool problems only when they explicitly called
// report_need, which rarely happened, so broken tools went unnoticed. The
// metered tool wrapper now feeds every failing tool call into this tracker;
// after `threshold` failures of the SAME tool inside one task (or chat session),
// a tool_error request is filed automatically — deduplicated per tool+task so a
// flapping tool doesn't spam the inbox.

const (
	toolErrorThreshold = 3               // consecutive-ish failures before auto-report
	toolErrorWindow    = 30 * time.Minute // failure counting window
	toolErrorCooldown  = 6 * time.Hour   // min gap between auto-reports for the same tool+task
)

type toolErrorRecorder interface {
	Create(db.AgentRequestCreate) (*db.AgentRequest, error)
}

type toolFailureState struct {
	count   int
	lastErr string
	firstAt time.Time
}

type toolErrorTracker struct {
	mu       sync.Mutex
	failures map[string]*toolFailureState
	cooldown map[string]time.Time
}

var globalToolErrorTracker = newToolErrorTracker()

func newToolErrorTracker() *toolErrorTracker {
	return &toolErrorTracker{
		failures: map[string]*toolFailureState{},
		cooldown: map[string]time.Time{},
	}
}

// record counts one tool failure and returns true when a request was filed.
func (t *toolErrorTracker) record(store toolErrorRecorder, toolKey, agentKey string, taskID int64, errMsg string) bool {
	if store == nil || strings.TrimSpace(toolKey) == "" {
		return false
	}
	now := time.Now()
	key := fmt.Sprintf("%d|%s", taskID, toolKey)

	t.mu.Lock()
	// Opportunistic cleanup so long-running processes don't grow the maps.
	for k, st := range t.failures {
		if now.Sub(st.firstAt) > toolErrorWindow {
			delete(t.failures, k)
		}
	}
	for k, at := range t.cooldown {
		if now.Sub(at) > toolErrorCooldown {
			delete(t.cooldown, k)
		}
	}
	if at, ok := t.cooldown[key]; ok && now.Sub(at) < toolErrorCooldown {
		t.mu.Unlock()
		return false // already reported recently — keep counting silently
	}
	st := t.failures[key]
	if st == nil || now.Sub(st.firstAt) > toolErrorWindow {
		st = &toolFailureState{firstAt: now}
		t.failures[key] = st
	}
	st.count++
	st.lastErr = errMsg
	count, lastErr := st.count, st.lastErr
	if count < toolErrorThreshold {
		t.mu.Unlock()
		return false
	}
	// Filing the report: reset the counter and start the cooldown so the same
	// flapping tool doesn't spam one request per failure burst.
	delete(t.failures, key)
	t.cooldown[key] = now
	t.mu.Unlock()

	taskPtr := new(int64)
	*taskPtr = taskID
	var taskPtrArg *int64
	if taskID > 0 {
		taskPtrArg = taskPtr
	}
	details := fmt.Sprintf("The `%s` tool returned an error %d times while an agent was working on this task.\n\nLast error:\n%s\n\nRecommendation: check the %s tool's configuration/credentials and fix or replace it if it is broken.", toolKey, count, lastErr, toolKey)
	context := "Automatic report: BEHEMOTH detected repeated failures of this tool during a task run."
	if taskID > 0 {
		context = fmt.Sprintf("Automatic report: BEHEMOTH detected repeated failures of this tool while working on task #%d.", taskID)
	}
	req, err := store.Create(db.AgentRequestCreate{
		AgentKey:  agentKey,
		TaskID:    taskPtrArg,
		Kind:      db.AgentRequestKindToolError,
		Urgency:   db.AgentRequestUrgencyNormal,
		Title:     fmt.Sprintf("Tool keeps failing: %s", toolKey),
		Details:   details,
		Context:   context,
		Extra:     map[string]any{"tool": toolKey, "failures": count, "auto": true},
	})
	if err != nil {
		log.Printf("[toolerror] auto-report %s: %v", toolKey, err)
		return false
	}
	log.Printf("[toolerror] auto-reported %s (task=%d, failures=%d) as agent request #%d", toolKey, taskID, count, req.ID)
	return true
}

// handleToolError is wired as the metered-tool error hook (see server.go).
func (s *Server) handleToolError(toolKey, agentKey string, taskID int64, errMsg string) {
	st := s.agentRequestStore()
	if st == nil {
		return
	}
	globalToolErrorTracker.record(st, toolKey, agentKey, taskID, errMsg)
}