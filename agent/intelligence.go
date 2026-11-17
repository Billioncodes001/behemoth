package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Missing host/setting means off. Rechecked on every write for running sessions.
var IntelligenceEnabled func() bool
var IntelligenceRecord func(context.Context, int64, int64, string, db.IntelligenceInput) (int64, error)
var CredentialRecorded func()

func intelligenceEnabled() bool { return IntelligenceEnabled != nil && IntelligenceEnabled() }
func intelligenceSchema() map[string]any {
	return obj(map[string]any{
		"kind":       map[string]any{"type": "string", "enum": []string{"credential", "lead", "sensitive_data"}},
		"title":      str("Short title; must NOT contain raw passwords, tokens, or sensitive data"),
		"content":    str("Actual information obtained. For credentials, store username/password/token etc. as a JSON string; for sensitive data, include only a few samples, count, and file location — do NOT paste entire databases"),
		"evidence":   str("Authentic source: command/request/response/file location and key observations; never fabricate"),
		"confidence": map[string]any{"type": "string", "enum": []string{"observed", "inferred"}},
		"status":     str("Credentials: unverified/verified/invalid; Leads: pending/in_progress/dismissed/converted; Sensitive data: suspected/confirmed/dismissed. Defaults conservatively when omitted; 'verified' requires proof of successful authentication"),
		"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
	}, "kind", "title", "content", "evidence", "confidence")
}
func (t *ToolSet) saveIntelligence(ctx context.Context, nodeID int64, in db.IntelligenceInput) (int64, error) {
	if !intelligenceEnabled() || IntelligenceRecord == nil {
		return 0, fmt.Errorf("automatic task intelligence recording is disabled")
	}
	taskID := t.taskID
	if taskID <= 0 {
		taskID = RunInfoFrom(ctx).TaskID
	}
	if taskID <= 0 {
		return 0, fmt.Errorf("task intelligence requires current task context")
	}
	if nodeID <= 0 {
		nodeID = t.ownerNode
	}
	if nodeID <= 0 {
		nodeID = RunInfoFrom(ctx).IntentID
	}
	id, err := IntelligenceRecord(ctx, taskID, nodeID, t.worker, in)
	if err == nil {
		t.writes.Intelligence++
	}
	return id, err
}
func (t *ToolSet) recordIntelligence() actool.CoreTool {
	return writeTool("record_intelligence", "Record credentials, important leads, or sensitive data actually obtained in the current task. Task and execution source are bound by the system; discovering credentials does not equal successful verification. Duplicate records are deduplicated. Service credentials in insert_assets.auth are registered automatically, so no duplicate call is needed.", intelligenceSchema(), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var in db.IntelligenceInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return actool.Errorf("invalid intelligence parameters"), nil
		}
		id, err := t.saveIntelligence(ctx, 0, in)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text(fmt.Sprintf("intelligence recorded: %d", id)), nil
	})
}
func intelligenceWorkflow(ctx context.Context, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	enabled := intelligenceEnabled() && RunInfoFrom(ctx).TaskID > 0
	out := make([]actool.CoreTool, 0, len(tools))
	hasRecord := false
	hasFact := false
	for _, tool := range tools {
		if tool.Name() == "record_intelligence" {
			if !enabled {
				continue
			}
			hasRecord = true
		}
		if tool.Name() == "record_fact" {
			raw, _ := json.Marshal(tool.InputSchema())
			var schema map[string]any
			if json.Unmarshal(raw, &schema) == nil {
				props, _ := schema["properties"].(map[string]any)
				if props != nil {
					delete(props, "intelligence")
					if enabled {
						props["intelligence"] = map[string]any{"type": "array", "maxItems": 20, "description": "Write back intelligence together with the fact in a single call (same fields as record_intelligence; no separate call needed)", "items": intelligenceSchema()}
						hasFact = true
					}
				}
				tool = DecorateTool(tool, tool.Description(), schema)
			}
		}
		out = append(out, tool)
	}
	guide := ""
	if enabled && (hasRecord || hasFact) {
		guide = "\n\n**Task Intelligence Recording (Enabled)**: When you discover credentials, actionable leads, or authentic sensitive data, write them back in structured form immediately without waiting for user prompts; check for any missed items before finishing. `record_fact` can attach an `intelligence` array (supported on both single facts and elements of batch `facts`); or call `record_intelligence` directly if available. `insert_assets.auth` is automatically registered by the backend — do not duplicate. Record only new, high-value information; ordinary fingerprints/port states remain regular facts. `title` must NOT contain raw secrets; `content` carries the actual values and `evidence` the source. Credentials default to `unverified` and should only be marked `verified` when authentication actually succeeds; inferred items must use `inferred`; sensitive data should note type, count, a few samples, and file location — never paste entire databases."
	}
	return out, guide
}
