package agent

import (
	"context"
	actool "github.com/Autumn-27/norma/tool"
)

type findingReviewKey struct{}

// Historical consolidation has a narrower capability set than new reporting.
func WithFindingCaseReview(ctx context.Context) context.Context {
	return context.WithValue(ctx, findingReviewKey{}, true)
}
func isFindingCaseReview(ctx context.Context) bool {
	v, _ := ctx.Value(findingReviewKey{}).(bool)
	return v
}

func historicalFindingCaseTools(tools []actool.CoreTool) []actool.CoreTool {
	allowed := map[string]bool{}
	for _, name := range []string{"search_finding_duplicates", "get_finding_record", "merge_finding_records", "suggest_finding_merge", "get_finding_case", "update_finding_case_report", "complete_finding_case_review", "get_finding_traffic", "traffic_search", "traffic_get", "traffic_blob", "get_task_node_detail", "list_task_findings", "get_task_graph", "list_task_worker_traces", "get_task_worker_trace", "Read"} {
		allowed[name] = true
	}
	out := make([]actool.CoreTool, 0, len(tools))
	for _, tool := range tools {
		if allowed[tool.Name()] {
			out = append(out, tool)
		}
	}
	return out
}

// This guidance is appended to the runtime prompt, including editable old prompts.
// Never reintroduce unbound tools or recreate a deleted Reporter.
func findingCaseWorkflow(key string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if key != "reporter" {
		return tools, ""
	}
	has := map[string]bool{}
	for _, t := range tools {
		has[t.Name()] = true
	}
	if !has["search_finding_duplicates"] || !has["merge_finding_records"] || !has["get_finding_case"] || !has["update_finding_case_report"] {
		return tools, ""
	}
	return tools, `

[Consolidating Multiple Reports of the Same Vulnerability] Retain this standalone report and do not overwrite other original reports. After saving this report, call search_finding_duplicates(finding_id=standalone record ID) to paginate through candidate summaries in the same task (sorted by score; strong = same vulnerability class + overlapping assets, check first; weak = does not have both, check hit_reasons for reference only), and call get_finding_record as needed to inspect evidence. Never merge based solely on similar vulnerability class, title, token, login entry, or severity; verify target, endpoint, parameter, privilege boundary, root cause, and actual verification evidence. Process only within the same task, respecting manual rejections and finding_case_blocks.
[Judgment Criteria] If evidence shows that the endpoint/route, handler or backend component, vulnerable parameter, or missing check belongs to different code paths, judge as independent and state the respective evidence. Similarity or difference in path, endpoint, login entry, token, title, or vulnerability class alone cannot prove same or different root cause. Call merge_finding_records(task_id, finding_ids, title, reason) directly ONLY when the root cause is definitively identical. Call suggest_finding_merge ONLY when specific commonalities exist (records point with evidence to the same endpoint, parameter, component, or missing check) but key evidence confirming a shared root cause is missing; submit one group covering 2..20 records in the same task rather than splitting into pairwise suggestions. Sharing only vulnerability class or asset without specific commonalities must not be suggested; keep independent when uncertain. Do not re-report, delete records, or re-probe targets. During manual selection review, judge only the selected records and do not include unselected records (existing group members may serve as report context).
When merged or an existing case_id is present, call get_finding_case to record the actual version, paginate through all members, and call get_finding_record / get_finding_traffic as needed to read original reports, PoCs, and saved traffic. When root cause is clear, merging is not blocked by the unified report; subsequently use update_finding_case_report to save the unified report. The unified report must contain substantive Overview, Impact, Prerequisites, Reproduction Steps, Evidence, PoC, Root Cause Analysis, and Remediation sections without truncation; severity and severity_reason must be based on verified impact rather than simply taking the highest member severity. On version conflict, re-read materials and regenerate rather than retrying with a bumped version.`
}

const historicalFindingReviewGuidance = `

[Historical Review Mode — Overrides New Report Writing & Auto Traffic Binding Guidance] This session only reviews and consolidates existing reports. Even if an original report is empty or pending update, only note the missing status — NEVER call update_finding_report, report_finding, or bind_finding_traffic, never modify original titles, severities, statuses, evidence, or reports, and never run Bash, write files, or re-probe targets.
First call get_finding_record for each selected record; reuse existing original reports directly as review material. Check for identical underlying defects only within the selected scope, reading existing evidence as needed. When structured evidence shows different endpoints/routes, handlers/backend components, parameters, or missing checks on distinct code paths, judge as independent; similar type, asset, title, token, or login entry alone is insufficient. Save a suspected group covering 2..20 records only when specific commonalities are clear but key root-cause evidence is missing; otherwise keep independent. Respect same-task constraints and manual rejections.
For existing or newly created folders, read all members and use update_finding_case_report to write a complete, up-to-date unified report (which is separate and does not overwrite original reports). Finally, you MUST call complete_finding_case_review to submit verdict (independent/merged/suggested), reason, and root_cause_evidence for every selected finding_id, along with a summary. Completion may only be announced after server validation passes.`
