package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/behemoth/db"
)

func TestFullEngagementReportMarkdown(t *testing.T) {
	now := time.Now()
	intentNode := &db.Node{
		ID:        10,
		Kind:      db.KindIntent,
		State:     "done",
		Priority:  9,
		CreatedAt: now.Add(-10 * time.Minute),
		Payload:   json.RawMessage(`{"summary":"Enumerate and test /api/v1/users for SQL injection","result":"Confirmed boolean/error-based SQLi on id parameter"}`),
	}
	factNode := &db.Node{
		ID:        11,
		Kind:      db.KindFact,
		CreatedAt: now.Add(-8 * time.Minute),
		Payload:   json.RawMessage(`{"summary":"Endpoint /api/v1/users reflects raw PostgreSQL syntax errors","confidence":"observed","evidence":"ERROR: unterminated quoted string at or near \"'1\""}`),
	}
	findingNode := &db.Node{
		ID:        12,
		FindingID: 501,
		Kind:      db.KindFinding,
		CreatedAt: now.Add(-5 * time.Minute),
		Payload:   json.RawMessage(`{"vulnclass":"sqli","name":"Unauthenticated SQL Injection in /api/v1/users","severity":"critical","summary":"The id query parameter is concatenated directly into SQL.","evidence":"curl -i 'https://target.local/api/v1/users?id=1%27'"}`),
	}
	goalNode := &db.Node{
		ID:      1,
		Kind:    db.KindGoal,
		State:   "met",
		Payload: json.RawMessage(`{"text":"Identify and verify high-severity vulnerabilities on target.local","proof":"Verified SQLi in /api/v1/users"}`),
	}

	nodeID := int64(12)
	dbFinding := &db.DBFinding{
		ID:        501,
		NodeID:    &nodeID,
		VulnClass: "sqli",
		Name:      "Unauthenticated SQL Injection in /api/v1/users",
		Severity:  "critical",
		Status:    "confirmed",
		Summary:   "The id query parameter is concatenated directly into SQL.",
		Evidence:  "curl -i 'https://target.local/api/v1/users?id=1%27'",
		Report:    "## Overview\n\nConfirmed SQLi.\n\n## Reproduction Steps\n\n### Step 1: Send Payload\n\nSend single quote.",
		CreatedAt: now.Add(-5 * time.Minute),
		AssetIDs:  []int64{100},
		TrafficBindings: []db.FindingTrafficBinding{
			{
				ID:   77,
				Role: "trigger",
				Note: "SQL error response packet",
				Snapshot: db.TrafficEvidenceSnapshot{
					Method:   "GET",
					URL:      "https://target.local/api/v1/users?id=1'",
					Status:   500,
					ReqHead:  "GET /api/v1/users?id=1' HTTP/1.1\r\nHost: target.local",
					RespHead: "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json",
				},
			},
		},
	}

	md := Markdown(Input{
		TaskID:      "42",
		Title:       "Target.local Full Pentest",
		Goal:        "Assess target.local web APIs",
		Status:      "done",
		Scope:       []string{"root_domain:target.local"},
		CreatedAt:   now.Add(-15 * time.Minute),
		GeneratedAt: now,
		AssetCounts: map[string]int{"endpoint": 1, "subdomain": 1},
		Assets: []AssetEntry{
			{ID: 100, Type: "endpoint", Label: "https://target.local/api/v1/users", Host: "target.local", Extra: "PostgreSQL API"},
		},
		AssetLabels: map[int64]string{100: "https://target.local/api/v1/users"},
		Goals:       []*db.Node{goalNode},
		Edges:       []db.Edge{{From: 1, Rel: "proved_by", To: 12}, {From: 10, Rel: "yields", To: 11}, {From: 10, Rel: "yields", To: 12}},
		Intents: []IntentTrace{
			{
				Node:       intentNode,
				YieldedIDs: []int64{11, 12},
				Steps: []db.Activity{
					{ID: 1, Kind: "tool", Tool: "bash", Summary: "curl -sk 'https://target.local/api/v1/users?id=1%27'"},
				},
			},
		},
		Facts:      []*db.Node{factNode},
		Findings:   []*db.Node{findingNode},
		DBFindings: []*db.DBFinding{dbFinding},
		FindingChains: map[int64][]*db.Node{
			12: {intentNode, factNode, findingNode},
		},
		Intelligence: []*db.Intelligence{
			{
				ID:        9,
				CreatedAt: now,
				IntelligenceInput: db.IntelligenceInput{
					Kind:       "credential",
					Title:      "Extracted DB Admin Hash",
					Content:    "postgres:$2b$12$examplehash",
					Evidence:   "SELECT usename, passwd FROM pg_shadow;",
					Confidence: "observed",
					Status:     "confirmed",
				},
			},
		},
		Artifacts: []ArtifactFile{
			{
				Path:        "i10/exploit_sqli.py",
				Size:        245,
				ModTime:     now,
				IntentID:    10,
				IntentTitle: "Enumerate and test /api/v1/users for SQL injection",
				Preview:     "import requests\nprint(requests.get('https://target.local/api/v1/users?id=1\\x27').text)",
			},
		},
	})

	for _, want := range []string{
		"## 1. Executive Summary",
		"## 2. Assessment Objectives & Operational Rules",
		"## 3. Discovered Attack Surface & Asset Inventory",
		"## 4. End-to-End Testing Process & Execution Timeline",
		"### Phase 1 — Intent `#10`",
		"Executed Tool & Command Trace:",
		"## 5. Confirmed Vulnerability Findings",
		"Attack Chain Lineage (How This Finding Was Reached)",
		"Verification Proof / Raw PoC Evidence",
		"Captured HTTP Traffic Evidence",
		"## 6. Captured Credentials, Sensitive Data & Intelligence",
		"## 7. Reconnaissance Facts & Technical Observations",
		"## 8. Run Artifacts & Workspace Files",
		"i10/exploit_sqli.py",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("report missing expected section/content %q:\n%s", want, md)
		}
	}
}
