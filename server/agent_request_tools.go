package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
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
		"Report a need to the BEHEMOTH operators so it can be addressed in a future update. Three situations call for it: (1) kind=tool/capability/integration/infra/data — the platform lacks a tool, capability, integration, API key/credential or data source you need; (2) kind=tool_error — a platform tool keeps failing for you (call it after the SAME tool failed 2+ times in this task): put the tool name and the exact error in details, plus what you were trying to do and any workaround you found; (3) kind=resource — the task clearly needs more computing power than the current server provides (extremely slow scans, OOM kills, timeouts from CPU/RAM starvation): describe the bottleneck and SUGGEST a specific server upgrade in details (e.g. 'upgrade to 8 vCPU / 16 GB RAM' or 'add GPU for browser-heavy crawling'). One call per distinct need, with a concise title, urgency (high = currently blocking this task), details (what exactly happened/what you need and, for tool_error and resource, a one-line 'Recommendation: …' the operator can act on) and context (what task phase / target / URL you were working on). After reporting, continue with the best available approach; do not stop the task waiting for the request.",
		objSchema(map[string]any{
			"title":   strParam("One-line summary, e.g. 'PDF parsing tool for report attachments' or 'sqlmap tool keeps timing out' or 'Need more CPU/RAM for large scans'"),
			"kind":    map[string]any{"type": "string", "enum": db.AgentRequestKinds, "description": "tool/capability/integration/infra/data = something is missing; tool_error = a platform tool keeps failing; resource = the task needs more computing power (default capability)"},
			"urgency": map[string]any{"type": "string", "enum": db.AgentRequestUrgencies, "description": "low = nice-to-have, normal = would improve results, high = currently blocking the task (default normal)"},
			"details": strParam("What exactly happened / what you need and why. For tool_error include the tool name and exact error message. For resource include the bottleneck (CPU/RAM/IO) and a specific suggested server upgrade. End with 'Recommendation: <what the operator should do>'."),
			"context": strParam("What you were working on when you hit this: task phase, target, URL or the step that made it obvious"),
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
