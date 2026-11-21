package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// report_need: the agent → developer capability-request channel. Whenever an
// agent realizes the platform lacks a tool/capability/integration/infra/data
// source it needs, it files one request; the row lands in the operator's
// Agent Requests inbox (System → Agent Requests) and lights the top-bar
// alerts bell so the gap is picked up for the next update.

// agentRequestTools returns the agent request tools.
func (s *Server) agentRequestTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolReportNeed()}
}

// agentRequestStore returns the shared store (nil when no database).
func (s *Server) agentRequestStore() *db.AgentRequestStore {
	if s.m == nil || s.m.pg == nil {
		return nil
	}
	return s.m.pg.AgentRequests()
}

// toolReportNeed exposes report_need.
func (s *Server) toolReportNeed() actool.CoreTool {
	return wrTool("report_need",
		"Report a missing tool, capability, integration, infrastructure or data source to the ARTEX operators so it can be added in a future update. Call it the moment you realize the platform lacks something you need for the task (e.g. no tool for X, an integration that is not configured, missing API keys/credentials, a capability that has to be built) — one call per distinct need, with a concise title, kind, urgency (high = currently blocking this task), details (what exactly you need and why, candidate tools/APIs you know of) and context (where you hit the gap). After reporting, continue with the best available approach; do not stop the task waiting for the request.",
		objSchema(map[string]any{
			"title":   strParam("One-line summary of the need, e.g. 'PDF parsing tool for report attachments'"),
			"kind":    map[string]any{"type": "string", "enum": db.AgentRequestKinds, "description": "What kind of need this is (default capability)"},
			"urgency": map[string]any{"type": "string", "enum": db.AgentRequestUrgencies, "description": "low = nice-to-have, normal = would improve results, high = currently blocking the task (default normal)"},
			"details": strParam("What exactly you need and why: desired behavior, candidate tools/APIs, and what you already tried"),
			"context": strParam("Where you hit the gap: task phase, target, URL or error that made it obvious"),
			"task_id": map[string]any{"type": "integer", "description": "Related task id (defaults to the current task when running inside one)"},
		}, "title"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Title   string `json:"title"`
				Kind    string `json:"kind"`
				Urgency string `json:"urgency"`
				Details string `json:"details"`
				Context string `json:"context"`
				TaskID  int64  `json:"task_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			if strings.TrimSpace(a.Title) == "" {
				return actool.Errorf("title is required"), nil
			}
			st := s.agentRequestStore()
			if st == nil {
				return actool.Errorf("agent request store is unavailable (no database)"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			var taskPtr *int64
			if a.TaskID > 0 {
				v := a.TaskID
				taskPtr = &v
			} else if ri.TaskID > 0 {
				v := ri.TaskID
				taskPtr = &v
			}
			req, err := st.Create(db.AgentRequestCreate{
				AgentKey:  agent.AgentKeyFrom(ctx),
				TaskID:    taskPtr,
				SessionID: ri.SessionID,
				Kind:      a.Kind,
				Urgency:   a.Urgency,
				Title:     a.Title,
				Details:   a.Details,
				Context:   a.Context,
			})
			if err != nil {
				return jsonResult(map[string]any{"error": err.Error()})
			}
			return jsonResult(map[string]any{
				"created":      true,
				"request":      req,
				"instructions": "The need is now in the operator's Agent Requests inbox (top-bar alerts bell) and will be considered for a future update. Continue the task with the best available approach.",
			})
		})
}
