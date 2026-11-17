// Package report renders a deliverable, end-to-end penetration testing Markdown
// report from the exploration graph, standalone findings table, worker execution
// traces, captured HTTP traffic evidence, task intelligence, and workspace artifacts.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// ArtifactFile describes a file generated in the task workspace (tasks/<id>/...).
type ArtifactFile struct {
	Path        string
	Size        int64
	ModTime     time.Time
	IntentID    int64
	IntentTitle string
	Preview     string // optional inline content preview for small scripts/text files
}

// IntentTrace bundles an exploration intent node with its lineage edges and worker tool steps.
type IntentTrace struct {
	Node       *db.Node
	DerivedIDs []int64       // parent fact/finding node IDs (derived_from)
	YieldedIDs []int64       // child fact/finding node IDs (yields)
	Steps      []db.Activity // worker execution trace steps
}

// AssetEntry represents a discovered or scoped asset for the engagement report.
type AssetEntry struct {
	ID    int64
	Type  string
	Label string
	Host  string
	Extra string
}

// Input bundles everything needed to render a comprehensive engagement report.
type Input struct {
	TaskID      string
	Title       string
	Goal        string
	Status      string
	Scope       []string
	CreatedAt   time.Time
	CompletedAt *time.Time
	GeneratedAt time.Time

	AssetCounts   map[string]int
	Assets        []AssetEntry
	AssetLabels   map[int64]string
	Constraints   []db.Constraint
	Hints         []*db.Node
	Goals         []*db.Node
	Edges         []db.Edge
	Intents       []IntentTrace
	Facts         []*db.Node
	Findings      []*db.Node      // exploration graph finding nodes (backward compatible)
	DBFindings    []*db.DBFinding // standalone findings with Report, Evidence, TrafficBindings
	FindingChains map[int64][]*db.Node
	Intelligence  []*db.Intelligence
	Artifacts     []ArtifactFile
}

type findingView struct {
	ID              int64
	NodeID          int64
	VulnClass       string
	Name            string
	Severity        string
	Status          string
	Summary         string
	PoC             string
	Report          string
	Worker          string
	CreatedAt       time.Time
	AssetIDs        []int64
	TrafficBindings []db.FindingTrafficBinding
}

func extractEvidenceString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		PoC      string `json:"poc"`
		Evidence string `json:"evidence"`
		Text     string `json:"text"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		if obj.PoC != "" {
			return strings.TrimSpace(obj.PoC)
		}
		if obj.Evidence != "" {
			return strings.TrimSpace(obj.Evidence)
		}
		if obj.Text != "" {
			return strings.TrimSpace(obj.Text)
		}
	}
	return strings.TrimSpace(string(raw))
}

func parseFinding(n *db.Node) findingView {
	var p struct {
		VulnClass string          `json:"vulnclass"`
		Name      string          `json:"name"`
		Severity  string          `json:"severity"`
		Summary   string          `json:"summary"`
		Evidence  json.RawMessage `json:"evidence"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return findingView{
		ID:        n.FindingID,
		NodeID:    n.ID,
		VulnClass: p.VulnClass,
		Name:      p.Name,
		Severity:  p.Severity,
		Status:    "confirmed",
		Summary:   p.Summary,
		PoC:       extractEvidenceString(p.Evidence),
		Worker:    n.Owner,
		CreatedAt: n.CreatedAt,
		AssetIDs:  n.Anchors,
	}
}

func fromDBFinding(f *db.DBFinding) findingView {
	var nodeID int64
	if f.NodeID != nil {
		nodeID = *f.NodeID
	}
	return findingView{
		ID:              f.ID,
		NodeID:          nodeID,
		VulnClass:       f.VulnClass,
		Name:            f.Name,
		Severity:        f.Severity,
		Status:          nz(f.Status, "pending"),
		Summary:         f.Summary,
		PoC:             strings.TrimSpace(f.Evidence),
		Report:          strings.TrimSpace(f.Report),
		Worker:          f.Worker,
		CreatedAt:       f.CreatedAt,
		AssetIDs:        f.AssetIDs,
		TrafficBindings: f.TrafficBindings,
	}
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}


func mergeFindings(nodes []*db.Node, dbRows []*db.DBFinding) []findingView {
	byNodeID := map[int64]findingView{}
	var out []findingView
	for _, f := range dbRows {
		if f == nil {
			continue
		}
		v := fromDBFinding(f)
		if v.NodeID > 0 {
			byNodeID[v.NodeID] = v
		} else {
			out = append(out, v)
		}
	}
	seenNode := map[int64]bool{}
	for _, n := range nodes {
		if n == nil {
			continue
		}
		seenNode[n.ID] = true
		if v, ok := byNodeID[n.ID]; ok {
			parsed := parseFinding(n)
			if v.PoC == "" {
				v.PoC = parsed.PoC
			}
			if v.Summary == "" {
				v.Summary = parsed.Summary
			}
			if v.Name == "" {
				v.Name = parsed.Name
			}
			if v.VulnClass == "" {
				v.VulnClass = parsed.VulnClass
			}
			out = append(out, v)
		} else {
			out = append(out, parseFinding(n))
		}
	}
	for nodeID, v := range byNodeID {
		if !seenNode[nodeID] {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := sevRank[out[i].Severity], sevRank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func nodeSummaryText(n *db.Node) string {
	if n == nil {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(n.Payload, &m); err == nil {
		for _, k := range []string{"summary", "text", "name", "title", "vulnclass"} {
			if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return strings.TrimSpace(string(n.Payload))
}

// Markdown renders the comprehensive end-to-end penetration test report.
func Markdown(in Input) string {
	var b strings.Builder
	findings := mergeFindings(in.Findings, in.DBFindings)

	// 1. Report Header & Engagement Overview
	fmt.Fprintf(&b, "# Penetration Testing & Security Assessment Report — %s\n\n", nz(in.Title, "Untitled Assessment"))
	if in.TaskID != "" {
		fmt.Fprintf(&b, "- **Task ID**: `#%s`\n", in.TaskID)
	}
	fmt.Fprintf(&b, "- **Primary Objective**: %s\n", nz(in.Goal, "(Not specified)"))
	if in.Status != "" {
		fmt.Fprintf(&b, "- **Engagement Status**: `%s`\n", strings.ToUpper(in.Status))
	}
	if len(in.Scope) > 0 {
		fmt.Fprintf(&b, "- **Authorized Scope**: `%s`\n", strings.Join(in.Scope, "`, `"))
	}
	if !in.CreatedAt.IsZero() {
		fmt.Fprintf(&b, "- **Started At**: %s\n", in.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	if in.CompletedAt != nil && !in.CompletedAt.IsZero() {
		fmt.Fprintf(&b, "- **Completed At**: %s\n", in.CompletedAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Fprintf(&b, "- **Report Generated**: %s\n\n", in.GeneratedAt.Format("2006-01-02 15:04:05"))

	// 2. Executive & Telemetry Summary
	totalSteps := 0
	doneIntents := 0
	for _, it := range in.Intents {
		totalSteps += len(it.Steps)
		if it.Node != nil && it.Node.State == "done" {
			doneIntents++
		}
	}
	sevCounts := map[string]int{}
	for _, f := range findings {
		sevCounts[strings.ToLower(nz(f.Severity, "info"))]++
	}

	b.WriteString("## 1. Executive Summary\n\n")
	fmt.Fprintf(&b, "- **Confirmed Findings**: **%d** (`%d Critical`, `%d High`, `%d Medium`, `%d Low`)\n",
		len(findings), sevCounts["critical"], sevCounts["high"], sevCounts["medium"], sevCounts["low"])
	if len(in.Intents) > 0 || len(in.Facts) > 0 || len(in.Artifacts) > 0 {
		fmt.Fprintf(&b, "- **Execution Telemetry**: **%d** intents planned (`%d` completed), **%d** tool/command steps executed, **%d** technical facts recorded, **%d** intelligence items captured, **%d** workspace artifacts archived\n",
			len(in.Intents), doneIntents, totalSteps, len(in.Facts), len(in.Intelligence), len(in.Artifacts))
	}
	b.WriteString("- **Attack Surface Summary**: ")
	if len(in.AssetCounts) == 0 {
		b.WriteString("none recorded\n\n")
	} else {
		var types []string
		for t := range in.AssetCounts {
			types = append(types, t)
		}
		sort.Strings(types)
		for i, t := range types {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s: %d", t, in.AssetCounts[t])
		}
		b.WriteString("\n\n")
	}

	if len(findings) > 0 {
		b.WriteString("### Vulnerability Severity Breakdown\n\n")
		b.WriteString("| # | Severity | Vulnerability / Finding | Class | Status | Traffic Evidence |\n")
		b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
		for i, f := range findings {
			title := nz(f.Name, nz(f.VulnClass, "Unclassified"))
			fmt.Fprintf(&b, "| %d | **%s** | %s | `%s` | `%s` | %d packet(s) |\n",
				i+1, strings.ToUpper(nz(f.Severity, "info")), strings.ReplaceAll(title, "|", "\\|"),
				nz(f.VulnClass, "-"), nz(f.Status, "pending"), len(f.TrafficBindings))
		}
		b.WriteString("\n")
	}

	writeSections2To8(&b, in, findings)
	return b.String()
}

func writeSections2To8(b *strings.Builder, in Input, findings []findingView) {
	// 3. Objectives, Operational Constraints & Strategic Guidance
	if len(in.Goals) > 0 || len(in.Constraints) > 0 || len(in.Hints) > 0 {
		b.WriteString("## 2. Assessment Objectives & Operational Rules\n\n")
		if len(in.Goals) > 0 {
			b.WriteString("### Verification Goals & Completion Proofs\n\n")
			provedBy := map[int64][]int64{}
			for _, e := range in.Edges {
				if e.Rel == "proved_by" {
					provedBy[e.From] = append(provedBy[e.From], e.To)
				}
			}
			b.WriteString("| Goal ID | Status | Target Objective | Proof / Evidence Nodes |\n")
			b.WriteString("| --- | --- | --- | --- |\n")
			for _, g := range in.Goals {
				var gp struct {
					Text  string `json:"text"`
					Proof string `json:"proof"`
				}
				_ = json.Unmarshal(g.Payload, &gp)
				status := strings.ToUpper(nz(g.State, "open"))
				proof := strings.TrimSpace(gp.Proof)
				if evIDs := provedBy[g.ID]; len(evIDs) > 0 {
					var refs []string
					for _, id := range evIDs {
						refs = append(refs, fmt.Sprintf("`#%d`", id))
					}
					if proof != "" {
						proof = fmt.Sprintf("%s (Evidence: %s)", proof, strings.Join(refs, ", "))
					} else {
						proof = "Evidence nodes: " + strings.Join(refs, ", ")
					}
				}
				if proof == "" {
					proof = "—"
				}
				fmt.Fprintf(b, "| `#%d` | **%s** | %s | %s |\n",
					g.ID, status, strings.ReplaceAll(nz(gp.Text, nodeSummaryText(g)), "|", "\\|"), strings.ReplaceAll(proof, "|", "\\|"))
			}
			b.WriteString("\n")
		}
		if len(in.Constraints) > 0 {
			b.WriteString("### Operational Constraints\n\n")
			for _, c := range in.Constraints {
				tag := "ALLOW"
				if c.Kind == "deny" {
					tag = "PROHIBITED"
				}
				fmt.Fprintf(b, "- **[%s]** %s\n", tag, c.Text)
			}
			b.WriteString("\n")
		}
		if len(in.Hints) > 0 {
			b.WriteString("### Operator Guidance & Hints\n\n")
			for _, h := range in.Hints {
				fmt.Fprintf(b, "- `[#%d]` %s\n", h.ID, nodeSummaryText(h))
			}
			b.WriteString("\n")
		}
	}

	// 4. Discovered Attack Surface & Scoped Assets
	if len(in.Assets) > 0 {
		b.WriteString("## 3. Discovered Attack Surface & Asset Inventory\n\n")
		b.WriteString("| Asset ID | Type | Target / Endpoint | Host | Details / Technologies |\n")
		b.WriteString("| --- | --- | --- | --- | --- |\n")
		limit := len(in.Assets)
		if limit > 150 {
			limit = 150
		}
		for _, a := range in.Assets[:limit] {
			fmt.Fprintf(b, "| `#%d` | `%s` | `%s` | `%s` | %s |\n",
				a.ID, a.Type, strings.ReplaceAll(nz(a.Label, "-"), "|", "\\|"),
				strings.ReplaceAll(nz(a.Host, "-"), "|", "\\|"), strings.ReplaceAll(nz(a.Extra, "-"), "|", "\\|"))
		}
		if len(in.Assets) > limit {
			fmt.Fprintf(b, "\n_Showing first %d of %d discovered assets._\n", limit, len(in.Assets))
		}
		b.WriteString("\n")
	}

	writeSections4To8(b, in, findings)
}

func writeSections4To8(b *strings.Builder, in Input, findings []findingView) {
	// 5. End-to-End Exploration & Execution Timeline (Start-to-Finish Process)
	if len(in.Intents) > 0 {
		b.WriteString("## 4. End-to-End Testing Process & Execution Timeline\n\n")
		b.WriteString("This section chronicles the complete autonomous testing workflow from initial reconnaissance through hypothesis generation, tool execution, and vulnerability verification.\n\n")

		nodeByID := map[int64]*db.Node{}
		for _, f := range in.Facts {
			nodeByID[f.ID] = f
		}
		for _, f := range in.Findings {
			nodeByID[f.ID] = f
		}

		for idx, it := range in.Intents {
			if it.Node == nil {
				continue
			}
			var ip struct {
				Summary string `json:"summary"`
				Title   string `json:"title"`
				Result  string `json:"result"`
			}
			_ = json.Unmarshal(it.Node.Payload, &ip)
			title := nz(ip.Summary, nz(ip.Title, nodeSummaryText(it.Node)))
			fmt.Fprintf(b, "### Phase %d — Intent `#%d`: %s\n\n", idx+1, it.Node.ID, title)
			fmt.Fprintf(b, "- **State**: `%s` | **Priority**: `%d` | **Timestamp**: %s",
				nz(it.Node.State, "open"), it.Node.Priority, it.Node.CreatedAt.Format("2006-01-02 15:04:05"))
			if len(it.DerivedIDs) > 0 {
				var parents []string
				for _, pid := range it.DerivedIDs {
					parents = append(parents, fmt.Sprintf("`#%d`", pid))
				}
				fmt.Fprintf(b, " | **Derived From**: %s", strings.Join(parents, ", "))
			}
			b.WriteString("\n\n")

			var actionSteps []db.Activity
			var finalResult string
			for _, st := range it.Steps {
				if st.Kind == "result" && strings.TrimSpace(st.Summary) != "" {
					finalResult = strings.TrimSpace(st.Summary)
					continue
				}
				if st.Tool != "" || st.Kind == "tool" || st.Kind == "tool_use" || st.Kind == "command" {
					actionSteps = append(actionSteps, st)
				}
			}
			if len(actionSteps) > 0 {
				b.WriteString("**Executed Tool & Command Trace:**\n\n")
				maxSteps := len(actionSteps)
				if maxSteps > 25 {
					maxSteps = 25
				}
				for sIdx, st := range actionSteps[:maxSteps] {
					toolName := nz(st.Tool, nz(st.Kind, "step"))
					sum := strings.TrimSpace(st.Summary)
					sum = strings.ReplaceAll(sum, "\n", " ⏎ ")
					if len(sum) > 260 {
						sum = sum[:260] + "..."
					}
					errTag := ""
					if st.IsError {
						errTag = " *(error)*"
					}
					fmt.Fprintf(b, "%d. `[%s]`%s `%s`\n", sIdx+1, toolName, errTag, strings.ReplaceAll(sum, "`", "'"))
				}
				if len(actionSteps) > maxSteps {
					fmt.Fprintf(b, "- _... plus %d additional execution steps (inspect via Worker Trace `#%d`)_\n", len(actionSteps)-maxSteps, it.Node.ID)
				}
				b.WriteString("\n")
			}

			conclusion := nz(ip.Result, finalResult)
			if conclusion != "" {
				fmt.Fprintf(b, "**Worker Outcome Summary:**\n\n> %s\n\n", strings.ReplaceAll(strings.TrimSpace(conclusion), "\n", "\n> "))
			}

			if len(it.YieldedIDs) > 0 {
				b.WriteString("**Yielded Graph Nodes:**\n\n")
				for _, yid := range it.YieldedIDs {
					if yn := nodeByID[yid]; yn != nil {
						fmt.Fprintf(b, "- **[%s `#%d`]** %s\n", strings.ToUpper(yn.Kind), yn.ID, nodeSummaryText(yn))
					} else {
						fmt.Fprintf(b, "- Node `#%d`\n", yid)
					}
				}
				b.WriteString("\n")
			}
		}
	}

	writeSections5To8(b, in, findings)
}

func writeSections5To8(b *strings.Builder, in Input, findings []findingView) {
	// 6. Confirmed Vulnerability Findings (Deep-Dive + Evidence + Traffic + Lineage)
	b.WriteString("## 5. Confirmed Vulnerability Findings\n\n")
	if len(findings) == 0 {
		b.WriteString("_No confirmed vulnerabilities were recorded during this run._\n\n")
	} else {
		for i, f := range findings {
			title := nz(f.Name, nz(f.VulnClass, "Unclassified Vulnerability"))
			fmt.Fprintf(b, "### 5.%d [%s] %s\n\n", i+1, strings.ToUpper(nz(f.Severity, "info")), title)
			if f.ID > 0 {
				fmt.Fprintf(b, "- **Finding ID**: `#%d`", f.ID)
				if f.NodeID > 0 {
					fmt.Fprintf(b, " (Graph Node `#%d`)", f.NodeID)
				}
				b.WriteString("\n")
			}
			if f.VulnClass != "" {
				fmt.Fprintf(b, "- **Vulnerability Class**: `%s`\n", f.VulnClass)
			}
			fmt.Fprintf(b, "- **Triage Status**: `%s`\n", nz(f.Status, "pending"))
			if !f.CreatedAt.IsZero() {
				fmt.Fprintf(b, "- **Discovered At**: %s\n", f.CreatedAt.Format("2006-01-02 15:04:05"))
			}
			if len(f.AssetIDs) > 0 && len(in.AssetLabels) > 0 {
				var labels []string
				for _, aid := range f.AssetIDs {
					if lbl := in.AssetLabels[aid]; lbl != "" {
						labels = append(labels, "`"+lbl+"`")
					}
				}
				if len(labels) > 0 {
					fmt.Fprintf(b, "- **Affected Assets**: %s\n", strings.Join(labels, ", "))
				}
			}
			b.WriteString("\n")

			if f.NodeID > 0 && len(in.FindingChains[f.NodeID]) > 0 {
				b.WriteString("#### Attack Chain Lineage (How This Finding Was Reached)\n\n")
				for stepIdx, ln := range in.FindingChains[f.NodeID] {
					fmt.Fprintf(b, "%d. **[%s `#%d`]** %s\n", stepIdx+1, strings.ToUpper(ln.Kind), ln.ID, nodeSummaryText(ln))
				}
				b.WriteString("\n")
			}

			if strings.TrimSpace(f.Summary) != "" {
				fmt.Fprintf(b, "#### Summary\n\n%s\n\n", strings.TrimSpace(f.Summary))
			}
			if f.PoC != "" {
				fmt.Fprintf(b, "#### Verification Proof / Raw PoC Evidence\n\n```\n%s\n```\n\n", f.PoC)
			}
			if f.Report != "" {
				b.WriteString("#### Detailed Technical Write-Up\n\n")
				b.WriteString(f.Report)
				b.WriteString("\n\n")
			}
			if len(f.TrafficBindings) > 0 {
				b.WriteString("#### Captured HTTP Traffic Evidence\n\n")
				for tIdx, tb := range f.TrafficBindings {
					fmt.Fprintf(b, "%d. **Traffic Binding `#%d` (%s)** — `%s %s` → HTTP `%d`\n",
						tIdx+1, tb.ID, nz(tb.Role, "evidence"), tb.Snapshot.Method, tb.Snapshot.URL, tb.Snapshot.Status)
					if strings.TrimSpace(tb.Note) != "" {
						fmt.Fprintf(b, "   - **Note**: %s\n", strings.TrimSpace(tb.Note))
					}
					if strings.TrimSpace(tb.Snapshot.ReqHead) != "" {
						fmt.Fprintf(b, "\n   **Request Headers:**\n   ```http\n   %s\n   ```\n",
							strings.ReplaceAll(strings.TrimSpace(tb.Snapshot.ReqHead), "\n", "\n   "))
					}
					if strings.TrimSpace(tb.Snapshot.RespHead) != "" {
						fmt.Fprintf(b, "\n   **Response Headers:**\n   ```http\n   %s\n   ```\n",
							strings.ReplaceAll(strings.TrimSpace(tb.Snapshot.RespHead), "\n", "\n   "))
					}
				}
				b.WriteString("\n")
			}
			b.WriteString("---\n\n")
		}
	}

	writeSections6To8(b, in)
}

func writeSections6To8(b *strings.Builder, in Input) {
	// 7. Captured Credentials, Sensitive Data & Task Intelligence
	if len(in.Intelligence) > 0 {
		b.WriteString("## 6. Captured Credentials, Sensitive Data & Intelligence\n\n")
		for i, item := range in.Intelligence {
			if item == nil {
				continue
			}
			fmt.Fprintf(b, "### 6.%d [%s] %s\n\n", i+1, strings.ToUpper(nz(item.Kind, "intel")), nz(item.Title, "Intelligence Item"))
			fmt.Fprintf(b, "- **Confidence**: `%s` | **Status**: `%s` | **Recorded At**: %s\n\n",
				nz(item.Confidence, "observed"), nz(item.Status, "new"), item.CreatedAt.Format("2006-01-02 15:04:05"))
			if strings.TrimSpace(item.Content) != "" {
				fmt.Fprintf(b, "%s\n\n", strings.TrimSpace(item.Content))
			}
			if strings.TrimSpace(item.Evidence) != "" {
				fmt.Fprintf(b, "**Supporting Evidence:**\n\n```\n%s\n```\n\n", strings.TrimSpace(item.Evidence))
			}
		}
	}

	// 8. Key Reconnaissance Facts & Technical Observations
	if len(in.Facts) > 0 {
		b.WriteString("## 7. Reconnaissance Facts & Technical Observations\n\n")
		maxFacts := len(in.Facts)
		if maxFacts > 100 {
			maxFacts = 100
		}
		for i, fn := range in.Facts[:maxFacts] {
			var fp struct {
				Summary    string          `json:"summary"`
				Confidence string          `json:"confidence"`
				Evidence   json.RawMessage `json:"evidence"`
			}
			_ = json.Unmarshal(fn.Payload, &fp)
			conf := nz(fp.Confidence, "observed")
			fmt.Fprintf(b, "### 7.%d Fact `#%d` (%s)\n\n", i+1, fn.ID, conf)
			fmt.Fprintf(b, "%s\n\n", nz(fp.Summary, nodeSummaryText(fn)))
			if ev := extractEvidenceString(fp.Evidence); ev != "" {
				if len(ev) > 1200 {
					ev = ev[:1200] + "\n...[truncated]..."
				}
				fmt.Fprintf(b, "```\n%s\n```\n\n", ev)
			}
		}
		if len(in.Facts) > maxFacts {
			fmt.Fprintf(b, "_Showing latest %d of %d recorded technical facts._\n\n", maxFacts, len(in.Facts))
		}
	}

	// 9. Run Artifacts & Workspace Files
	b.WriteString("## 8. Run Artifacts & Workspace Files\n\n")
	if len(in.Artifacts) == 0 {
		b.WriteString("_No workspace files or script artifacts were saved on disk for this task._\n\n")
	} else {
		b.WriteString("| File Path | Size (Bytes) | Originating Intent | Last Modified |\n")
		b.WriteString("| --- | --- | --- | --- |\n")
		for _, art := range in.Artifacts {
			intentRef := "—"
			if art.IntentID > 0 {
				if art.IntentTitle != "" {
					intentRef = fmt.Sprintf("`#%d` (%s)", art.IntentID, strings.ReplaceAll(art.IntentTitle, "|", "\\|"))
				} else {
					intentRef = fmt.Sprintf("`#%d`", art.IntentID)
				}
			}
			fmt.Fprintf(b, "| `%s` | %d | %s | %s |\n",
				strings.ReplaceAll(art.Path, "|", "\\|"), art.Size, intentRef, art.ModTime.Format("2006-01-02 15:04:05"))
		}
		b.WriteString("\n")

		for _, art := range in.Artifacts {
			if strings.TrimSpace(art.Preview) == "" {
				continue
			}
			fmt.Fprintf(b, "### Artifact Preview: `%s`\n\n", art.Path)
			fmt.Fprintf(b, "```\n%s\n```\n\n", strings.TrimSpace(art.Preview))
		}
	}
}

func nz(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
