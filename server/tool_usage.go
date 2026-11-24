package server

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
)

type toolUsageRecorder interface {
	InsertToolUsage(*db.ToolUsage) error
}

// toolErrorHook is invoked after every catalog tool call that returns an error
// result. It is wired to Server.handleToolError at startup (see server.go) and
// turns repeated failures into automatic tool_error agent requests.
var toolErrorHook func(toolKey, agentKey string, taskID int64, errMsg string)

// meteredTool records one row immediately before a catalog tool is invoked. It
// embeds the resolved tool so schema overrides, defaults and permission behavior
// remain unchanged.
type meteredTool struct {
	actool.CoreTool
	recorder toolUsageRecorder
	toolKey  string
	agentKey string
	ri       agent.RunInfo
}

func meterTool(t actool.CoreTool, recorder toolUsageRecorder, toolKey, agentKey string, ri agent.RunInfo) actool.CoreTool {
	if recorder == nil {
		return t
	}
	return &meteredTool{CoreTool: t, recorder: recorder, toolKey: toolKey, agentKey: agentKey, ri: ri}
}

func (m *meteredTool) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if m.agentKey != "" {
		// Attribute the call to the invoking agent for host tools that care
		// (report_need files its row under this agent key).
		ctx = agent.WithAgentKey(ctx, m.agentKey)
	}
	if err := m.recorder.InsertToolUsage(&db.ToolUsage{
		ToolKey:       m.toolKey,
		AgentKey:      m.agentKey,
		TaskID:        m.ri.TaskID,
		ExplorationID: m.ri.ExplorationID,
		IntentID:      m.ri.IntentID,
		SessionID:     m.ri.SessionID,
	}); err != nil {
		log.Printf("[toolusage] insert %s: %v", m.toolKey, err)
	}
	res, callErr := m.CoreTool.Call(ctx, input, tc)
	if toolErrorHook != nil && (callErr != nil || res.IsError) {
		msg := ""
		if callErr != nil {
			msg = callErr.Error()
		} else {
			msg = res.Flatten()
		}
		toolErrorHook(m.toolKey, m.agentKey, m.ri.TaskID, truncateToolErrorText(msg))
	}
	return res, callErr
}

// truncateToolErrorText keeps the auto-report payload bounded (rune-safe).
func truncateToolErrorText(s string) string {
	const max = 800
	r := []rune(strings.TrimSpace(s))
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return string(r)
}
