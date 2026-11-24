package agent

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/behemoth/db"
	actool "github.com/Autumn-27/norma/tool"
)

const findingIDGuidance = "\n\n**Finding ID Convention**: `finding_id` is the standalone vulnerability record ID; `finding_node_id` is the exploration node ID. The `id` field in `list_findings` / `list_task_findings` / `node_detail` / `get_task_node_detail` remains the exploration node ID — read `finding_id` from the same response for the standalone ID. `get_finding_traffic` / `bind_finding_traffic` use the standalone `finding_id`. Legacy `update_finding_report` still takes `finding_node_id` in its `finding_id` parameter. Do not pass the number on the first line of `report_finding` to traffic evidence tools, and do not guess other numbers if an ID error occurs."

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\nBy default, the Reporter Agent verifies and binds traffic before writing the report. Keep verification commands, key outputs, and existing authentic traffic IDs with their roles in `evidence` so the Reporter Agent can cross-check against execution traces; no extra packet lookup is needed just for binding. Explicit immediate binding is also supported: `traffic_refs` or `evidence_hint_id` can submit verified references (the latter reads structured references from the specified hint in this task); if any reference is invalid, the entire report fails. TCP/non-HTTP findings do not need these optional parameters. Returns `finding_id` (standalone record) and `finding_node_id` (exploration node)."
		case "add_hint", "add_task_hint":
			note = "\nWhen handing off a confirmed vulnerability, preserve the verified traffic IDs, roles, notes, and order in `traffic_refs` on the corresponding hint (top-level for single, or inside the corresponding `hints` element for batch), and specify which vulnerability it proves in `text`. Do not hand off text alone while dropping existing traffic references. Unverified candidates must not be passed as evidence."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**Traffic Evidence Handoff (Optional)**: Automatic binding is performed by the Reporter Agent after the vulnerability is recorded and before writing the report. Reporters should preserve verification commands, key outputs, and authentic traffic IDs with their roles in `evidence`, along with `intent_id` in task context for traceability; no extra packet lookup is needed just for binding. When Auto / Planner reports on behalf of a worker, do not drop existing references. `add_hint` / `add_task_hint` can hand off via `traffic_refs`; explicit immediate binding remains compatible via `traffic_refs` / `evidence_hint_id` on `report_finding`. For TCP or non-captured cases, register normally without guessing IDs or re-probing just to capture packets."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\nWhen a platform conversation has no task context, do not call `report_finding` directly; hand off to the corresponding task via `add_task_hint` for the task Agent to register, and verify with `list_task_findings`."
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\nBefore marking a goal complete, finish reporting/handing off existing evidence. Do not end the task or cancel Workers while evidence handoff is still pending; non-HTTP cases do not require waiting or forced packet capture."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**Pre-Report Automatic Traffic Binding (Enabled)**: You are responsible for verifying and binding traffic for this triggered vulnerability before writing the report. First obtain the explicit `finding_id` and `finding_node_id` from the `report_finding` JSON return or `get_task_node_detail` / `list_task_findings`. Read the vulnerability details, the execution trace of the corresponding intent, and the existing evidence list, prioritizing authentic IDs handed off by the reporter. If the verification was HTTP and traffic tools are available, filter candidates with `traffic_search` and verify each request/response with `traffic_get` to confirm it genuinely supports the vulnerability; domain and timestamp are for filtering only and do not prove attribution. Bind confirmed evidence in reproduction order via `bind_finding_traffic(finding_id, traffic_refs)`, selecting `baseline` / `proof` / `verification` / `supporting` and explaining the role. Operate only on this vulnerability; do not recreate findings or re-probe the target. After binding, call `get_finding_traffic` again to obtain the latest `version`, read the required bodies, and pass the actually read `version` as `evidence_version` to `update_finding_report` (whose `finding_id` parameter still takes `finding_node_id`). Existing bindings need not be duplicated. For TCP, uncaptured traffic, unavailable tools, or no exact match, skip automatic binding and write the report based on text/command evidence while noting the reason — never guess IDs. If binding fails, do not claim success; retain existing evidence and note the reason in the report."
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += "\n\n**Traffic ID Convention**: The traffic ID displayed/copied on the Traffic page is the exact `id` returned by `traffic_search`, and the raw string used by `traffic_get(id)` and `traffic_refs[].traffic_id`. It is not a list row number and does not change with pagination, sorting, or filtering. When handed a full ID, read and verify it directly with `traffic_get` without rewriting, truncating, or guessing; keep the full ID when citing traffic evidence in reports." + findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "Optional: verified traffic references corresponding to the specific vulnerability in this hint, preserving order; after handoff, report_finding can pass evidence_hint_id to carry these references.", "items": obj(map[string]any{"traffic_id": str("Authentic traffic ID"), "role": str("baseline / proof / verification / supporting"), "note": str("What conclusion this traffic supports")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d must be a hint node of this task (inherited hints cannot be used directly for binding)", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
