package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/behemoth/db"
)

// generateFindingReport requeues the reporter workflow for any finding — both
// task-based findings (with an exploration node_id) and standalone/Chat findings
// (where node_id is nil and update_finding_report addresses findings.id directly).
func (s *Server) generateFindingReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "Invalid finding ID")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if f == nil {
		writeErr(w, http.StatusNotFound, "Finding not found")
		return
	}
	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if reporter == nil {
		writeErr(w, http.StatusConflict, "The Report Writer agent (reporter) is missing; restart BEHEMOTH to re-seed built-in agents")
		return
	}
	if !reporter.Enabled {
		// Automatically enable the built-in reporter if an operator explicitly clicked "Generate steps and report"
		_, _ = s.m.pg.Exec(`UPDATE agents SET enabled = true WHERE id = $1`, reporter.ID)
		reporter.Enabled = true
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: reporter.Key}) == nil {
		writeErr(w, http.StatusServiceUnavailable, s.chatUnavailableReason())
		return
	}
	if s.ctx.Err() != nil {
		writeErr(w, http.StatusServiceUnavailable, "Server is shutting down")
		return
	}

	var taskID int64
	var taskDesc, taskGoal string
	if f.TaskID != nil {
		taskID = *f.TaskID
		if task := s.m.ResolveTask(strconv.FormatInt(taskID, 10)); task != nil {
			taskDesc, taskGoal = task.Description, task.Goal
		}
	}
	dto := findingFromDB(f, s.resolveFindingAssets([]*db.DBFinding{f}))
	var assetLabels []string
	for _, a := range dto.Assets {
		assetLabels = append(assetLabels, fmt.Sprintf("%s (%s)", a.Label, a.Type))
	}

	message := manualFindingReportMessage(f, taskID, assetLabels)
	conversation, err := s.m.pg.CreateConversation("reporter", fmt.Sprintf("Vulnerability Report · finding#%d", f.ID), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to create report conversation: "+err.Error())
		return
	}
	if err := s.m.pg.SetFindingReportConversationID(f.ID, conversation.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to link report conversation: "+err.Error())
		return
	}
	s.StartTriggeredRunWithConversation(
		"reporter",
		fmt.Sprintf("Generate Reproduction Steps & Report · finding#%d", f.ID),
		message,
		taskID,
		false,
		taskDesc,
		taskGoal, conversation.ID,
	)
	var nodeID int64
	if f.NodeID != nil && *f.NodeID > 0 {
		nodeID = *f.NodeID
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"queued":          true,
		"agent_key":       "reporter",
		"finding_id":      f.ID,
		"finding_node_id": nodeID,
		"conversation_id": conversation.ID,
	})
}

func manualFindingReportMessage(f *db.DBFinding, taskID int64, assetLabels []string) string {
	var b strings.Builder
	b.WriteString("[Manual Report & Reproduction Steps Generation] Author a comprehensive, structured technical vulnerability report in English for this confirmed finding using ONLY the recorded finding data and captured evidence. Do NOT execute live network probes (no curl/nmap/dig/Bash against the target), do NOT call insert_assets, do NOT create a new finding record, and do NOT alter or delete existing evidence.\n\n")
	if f.NodeID != nil && *f.NodeID > 0 {
		fmt.Fprintf(&b, "- Standalone Finding ID (`finding_id` for `get_finding_traffic`): %d\n", f.ID)
		fmt.Fprintf(&b, "- Exploration Node ID (`finding_node_id` for `get_task_node_detail` & `update_finding_report`): %d\n", *f.NodeID)
		if taskID > 0 {
			fmt.Fprintf(&b, "- Source Task ID (`task_id`): %d\n", taskID)
		}
	} else {
		fmt.Fprintf(&b, "- Standalone Finding ID (`finding_id` — use this exact integer ID for both `get_finding_traffic` and `update_finding_report`): %d\n", f.ID)
		b.WriteString("- Origin: Standalone Chat Security Assessment (no task container — do NOT call `get_task_node_detail`, `list_task_worker_traces`, or `search_finding_duplicates`; use the complete finding record & verbatim PoC evidence provided below plus `get_finding_traffic`).\n")
	}
	title := strings.TrimSpace(f.Name)
	if title == "" {
		title = f.VulnClass
	}
	fmt.Fprintf(&b, "- Title: %s\n- Vulnerability Class: %s\n- Severity: %s\n", title, f.VulnClass, strings.ToUpper(f.Severity))
	if len(assetLabels) > 0 {
		fmt.Fprintf(&b, "- Affected Assets: %s\n", strings.Join(assetLabels, ", "))
	}
	if strings.TrimSpace(f.Summary) != "" {
		fmt.Fprintf(&b, "\n### Recorded Summary\n%s\n", f.Summary)
	}
	if strings.TrimSpace(f.Evidence) != "" {
		fmt.Fprintf(&b, "\n### Recorded Verbatim Evidence / PoC\n```\n%s\n```\n", f.Evidence)
	}
	b.WriteString("\n### Workflow & Required Markdown Sections\n")
	b.WriteString("1. First call `get_finding_traffic(finding_id=" + strconv.FormatInt(f.ID, 10) + ")` to check bound HTTP packets and read `version` (an empty list is normal; proceed using the verbatim Evidence / PoC above without fabricating packets or running Bash).\n")
	if f.NodeID != nil && *f.NodeID > 0 && taskID > 0 {
		fmt.Fprintf(&b, "2. Call `get_task_node_detail(task_id=\"%d\", id=%d)` and `list_task_worker_traces(task_id=\"%d\")` if additional execution trace context is available.\n", taskID, *f.NodeID, taskID)
	}
	targetUpdateID := f.ID
	if f.NodeID != nil && *f.NodeID > 0 {
		targetUpdateID = *f.NodeID
	}
	b.WriteString("3. Write a detailed Markdown report strictly in English containing these exact top-level headings:\n")
	b.WriteString("   - `## Overview`\n   - `## Impact & Risk`\n   - `## Affected Scope`\n   - `## Reproduction Steps` (expand step-by-step using `### Step 1: ...`, `### Step 2: ...` with exact commands/requests and observed responses)\n   - `## Root Cause Analysis`\n   - `## Remediation`\n")
	fmt.Fprintf(&b, "4. Save the finished report immediately by calling `update_finding_report(finding_id=%d, report=<Full Markdown>, evidence_version=<version read from get_finding_traffic>)`, then conclude immediately and tell the user where the saved report can be viewed.", targetUpdateID)
	return b.String()
}
