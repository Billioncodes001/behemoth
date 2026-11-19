package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/server/patchmonitor"
	"github.com/Autumn-27/artex/server/tools"
)

func TestEnsureDefaultWordlistsAndListSecurityArsenal(t *testing.T) {
	tmp := t.TempDir()
	cat := tools.NewCatalog()
	s := &Server{
		dataDir:      tmp,
		toolCatalog:  cat,
		toolExecutor: tools.NewToolExecutor(cat, tools.DefaultExecutorConfig()),
	}
	s.ensureDefaultWordlists()
	wls := s.resolveWordlistPaths()
	if wls["common_web"] == "" || wls["api_routes"] == "" {
		t.Fatalf("expected default wordlists created, got %v", wls)
	}

	res, err := s.toolListSecurityArsenal().Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("list_security_arsenal error: %v", err)
	}
	var out map[string]any
	if len(res.Content) == 0 || json.Unmarshal([]byte(res.Content[0].Text), &out) != nil {
		t.Fatalf("unexpected arsenal JSON: %+v", res)
	}
	if out["wordlists"] == nil || out["catalog_tools"] == nil {
		t.Fatalf("missing wordlists or catalog_tools in arsenal response: %v", out)
	}
}

func TestStandaloneFindingReportUpdateAndInterceptRuleGovernance(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer pg.Close()

	s := &Server{
		m: &Manager{
			pg:          pg,
			interceptor: intercept.New(pg),
		},
	}

	// 1) Insert a standalone Chat finding (node_id IS NULL, task_id IS NULL) and update its report.
	var fid int64
	if err := pg.QueryRow(`INSERT INTO findings(vulnclass, name, severity, summary, evidence, status) VALUES('Misconfiguration', 'Cleartext HTTP', 'medium', 'HTTP exposed', 'curl -I http://example.com', 'pending') RETURNING id`).Scan(&fid); err != nil {
		t.Fatalf("insert standalone finding: %v", err)
	}
	repRes, err := s.toolUpdateFindingReport().Call(context.Background(), json.RawMessage(`{"finding_id":`+i64s(fid)+`,"report":"## Overview\n\nVerified cleartext HTTP exposure."}`), nil)
	if err != nil || repRes.IsError {
		t.Fatalf("update_finding_report failed on standalone finding id=%d: err=%v res=%+v", fid, err, repRes)
	}
	updatedFinding, err := pg.GetFinding(fid)
	if err != nil || updatedFinding == nil || !strings.Contains(updatedFinding.Report, "Verified cleartext HTTP exposure") {
		t.Fatalf("standalone finding report not persisted: err=%v finding=%+v", err, updatedFinding)
	}

	// 2) Verify intercept_default_rules_v4 disabled false-positive Deletion endpoint path,
	//    while immutable host-OS safety rules cannot be disabled via update_intercept_rule.
	rules, err := pg.ListInterceptRules()
	if err != nil {
		t.Fatalf("ListInterceptRules: %v", err)
	}
	var mkfsID, curlDelID int64
	for _, r := range rules {
		if r.Name == "[Built-in] Deletion endpoint path" && r.Enabled {
			t.Fatalf("expected Deletion endpoint path disabled by v4 migration, got enabled=true")
		}
		if r.Name == "[Built-in] Format disk mkfs" {
			mkfsID = r.ID
		}
		if r.Name == "[Built-in] curl / wget HTTP DELETE request" {
			curlDelID = r.ID
		}
	}
	if mkfsID > 0 {
		res, _ := s.toolUpdateInterceptRule().Call(context.Background(), json.RawMessage(`{"id":`+i64s(mkfsID)+`,"enabled":false}`), nil)
		if !res.IsError {
			t.Fatalf("expected disabling host-OS mkfs rule to be rejected, got %+v", res)
		}
	}
	if curlDelID > 0 {
		res, _ := s.toolUpdateInterceptRule().Call(context.Background(), json.RawMessage(`{"id":`+i64s(curlDelID)+`,"enabled":false}`), nil)
		if res.IsError {
			t.Fatalf("expected non-host rule update to succeed, got %+v", res)
		}
	}

	// 3) Verify standalone finding lineage graph returns non-empty nodes & edges
	req := httptest.NewRequest(http.MethodGet, "/api/exploration/findings/"+i64s(fid)+"/lineage", nil)
	req.SetPathValue("id", i64s(fid))
	w := httptest.NewRecorder()
	s.findingLineage(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("findingLineage status=%d body=%s", w.Code, w.Body.String())
	}
	var lineage struct {
		Nodes []TaskNodeDTO `json:"nodes"`
		Edges []EdgeDTO     `json:"edges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &lineage); err != nil || len(lineage.Nodes) < 3 || len(lineage.Edges) < 2 {
		t.Fatalf("expected synthetic standalone lineage graph, got err=%v lineage=%+v", err, lineage)
	}

	// 4) Verify Patch Monitor AutoMatchAuthorizedTargets correlates registered Assets by technology
	var assetID int64
	if err := pg.QueryRow(`INSERT INTO assets(type, domain, url, service_name, technologies) VALUES('service', 'portal.example.org', 'https://portal.example.org', 'PHP/8.2 Apache', ARRAY['PHP','Apache']) RETURNING id`).Scan(&assetID); err != nil {
		t.Fatalf("insert test asset: %v", err)
	}
	pm := patchmonitor.NewMonitor(pg.DB)
	matched, err := pm.AutoMatchAuthorizedTargets(nil)
	if err != nil {
		t.Fatalf("AutoMatchAuthorizedTargets: %v", err)
	}
	foundPortal := false
	for _, m := range matched {
		if m.Host == "portal.example.org" {
			foundPortal = true
			break
		}
	}
	if !foundPortal {
		t.Fatalf("expected portal.example.org (asset #%d) auto-matched into exploit_targets, got %+v", assetID, matched)
	}
}
