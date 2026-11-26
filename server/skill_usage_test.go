package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
	"github.com/Autumn-27/norma/skill"
)

func TestSkillAliasResolutionReconciliationAndClearMissing(t *testing.T) {
	m := proxyTestManager(t)
	skillDir := t.TempDir()
	wafDir := filepath.Join(skillDir, "waf-and-filter-bypass")
	_ = os.MkdirAll(wafDir, 0o755)
	_ = os.WriteFile(filepath.Join(wafDir, "SKILL.md"), []byte("---\nname: waf-and-filter-bypass\ndescription: WAF bypass playbook\n---\n## Bypass Steps\nUse chunked transfer.\n"), 0o644)

	reg, err := skill.LoadDir(skillDir)
	if err != nil {
		t.Fatalf("skill.LoadDir: %v", err)
	}
	wrapped := meterSkillTool(reg.Tool(), m.pg, reg, "planner", agent.RunInfo{})

	// 1. Calling shorthand alias "waf-bypass" resolves to "waf-and-filter-bypass" and records found=true!
	res, err := wrapped.Call(context.Background(), json.RawMessage(`{"name":"waf-bypass"}`), nil)
	if err != nil || res.IsError || !strings.Contains(res.Flatten(), `Skill "waf-and-filter-bypass" loaded`) {
		t.Fatalf("expected alias waf-bypass to resolve cleanly, err=%v res=%s", err, res.Flatten())
	}

	// 2. Seed one historical false-miss for an existing skill ("waf-and-filter-bypass")
	//    and one genuine unknown miss ("nonexistent-custom-playbook").
	_ = m.pg.InsertSkillUsage(&db.SkillUsage{Skill: "waf-and-filter-bypass", AgentKey: "planner", Found: false})
	_ = m.pg.InsertSkillUsage(&db.SkillUsage{Skill: "nonexistent-custom-playbook", AgentKey: "worker", Found: false})

	s := &Server{m: m, skillDir: skillDir}
	req := httptest.NewRequest(http.MethodGet, "/api/skills/missing", nil)
	rec := httptest.NewRecorder()
	s.fsMissingSkills(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fsMissingSkills got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "waf-and-filter-bypass") {
		t.Fatalf("expected existing skill reconciled out of missing list, got %s", body)
	}
	if !strings.Contains(body, "nonexistent-custom-playbook") {
		t.Fatalf("expected genuine missing skill retained before clear, got %s", body)
	}

	// 3. DELETE /api/skills/missing clears unresolved misses
	delReq := httptest.NewRequest(http.MethodDelete, "/api/skills/missing", nil)
	delRec := httptest.NewRecorder()
	s.fsClearMissingSkills(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("fsClearMissingSkills got %d: %s", delRec.Code, delRec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	s.fsMissingSkills(rec2, httptest.NewRequest(http.MethodGet, "/api/skills/missing", nil))
	if strings.Contains(rec2.Body.String(), "nonexistent-custom-playbook") {
		t.Fatalf("expected missing skills cleared, got %s", rec2.Body.String())
	}
}
