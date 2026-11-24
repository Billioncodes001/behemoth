package agent

import (
	"context"

	"github.com/Autumn-27/behemoth/db"
)

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

// Tool-use guidance is appended without replacing the user's editable prompt.
// It does not require capture or claim that unavailable traffic tools exist.
const findingTrafficGuidance = "\n\n**Vulnerability Traffic Evidence (Optional)**: When calling report_finding, if you have inspected HTTP requests/responses that confirm the vulnerability, pass authentic IDs in reproduction order via traffic_refs; domain and timestamp are only for candidate filtering and do not imply attribution. For TCP/non-HTTP vulnerabilities, uncaptured traffic, or no exact match, omit traffic_refs or pass [] and keep verifiable command output/logs in evidence (noting why traffic was not bound). Never guess IDs or re-probe solely to capture packets."

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
