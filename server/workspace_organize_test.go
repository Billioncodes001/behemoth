package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceDomainValidationZeroConflictOrganizeAndSearch(t *testing.T) {
	// 1. Validate domain filtering rejects bogus tokens, bounty platforms, and self host
	for _, bad := range []string{"1.27m", "3.05bpw", "bugcrowd.com", "console.internaldirective.org", "github.com", "report.json"} {
		if isValidTargetWorkspaceDomain(bad) {
			t.Fatalf("expected %q to be rejected as a target workspace domain", bad)
		}
	}
	for _, good := range []string{"inecnigeria.org", "api-prod.inecnigeria.org", "lms.federalpolyede.edu.ng", "news.lasustech.edu.ng"} {
		if !isValidTargetWorkspaceDomain(good) {
			t.Fatalf("expected %q to be accepted as a target workspace domain", good)
		}
	}

	s, _, req := trafficEvidenceServer(t)

	// 2. Seed polluted domains/ (subdomain split + empty bogus folders) AND a real Task file under tasks/<id>/domains/inecnigeria.org/exfil/
	task, err := s.m.CreateTask("Deep exploitation · inecnigeria.org", "Audit https://api-prod.inecnigeria.org", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	taskExfilDir := filepath.Join(s.m.dir, "tasks", task.ID, "domains", "inecnigeria.org", "exfil")
	if err := os.MkdirAll(taskExfilDir, 0o755); err != nil {
		t.Fatal(err)
	}
	taskFile := filepath.Join(taskExfilDir, "admin_dump.json")
	if err := os.WriteFile(taskFile, []byte(`{"ok":true,"rows":42}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Subdomain folder with a file + bogus empty folders (`1.27m`, `bugcrowd.com`)
	subDir := filepath.Join(s.m.dir, "domains", "api-prod.inecnigeria.org")
	_ = os.MkdirAll(subDir, 0o755)
	_ = os.WriteFile(filepath.Join(subDir, "swagger.json"), []byte(`{"openapi":"3.0.0"}`), 0o644)
	_ = os.MkdirAll(filepath.Join(s.m.dir, "domains", "1.27m", "evidence"), 0o755)
	_ = os.MkdirAll(filepath.Join(s.m.dir, "domains", "bugcrowd.com"), 0o755)

	// 3. Run POST /api/workspace/organize
	wOrg := req(http.MethodPost, "/api/workspace/organize", "{}")
	if wOrg.Code != http.StatusOK {
		t.Fatalf("POST /api/workspace/organize failed: %d %s", wOrg.Code, wOrg.Body.String())
	}
	var rep WorkspaceOrganizeReport
	if err := json.Unmarshal(wOrg.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.DomainsConsolidated < 1 || rep.TaskFilesSynced < 2 || rep.BogusRemoved < 2 {
		t.Fatalf("unexpected organize report: %+v", rep)
	}

	// Verify BOTH the original Task path (zero-conflict for resuming workers!) AND the unified domains/inecnigeria.org/exfil/admin_dump.json exist!
	if _, err := os.Stat(taskFile); err != nil {
		t.Fatalf("original task file must remain untouched for resuming workers: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.m.dir, "domains", "inecnigeria.org", "exfil", "admin_dump.json")); err != nil {
		t.Fatalf("expected synced file under domains/inecnigeria.org/exfil/admin_dump.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.m.dir, "domains", "inecnigeria.org", "swagger.json")); err != nil {
		t.Fatalf("expected consolidated subdomain file under domains/inecnigeria.org/swagger.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.m.dir, "domains", "1.27m")); !os.IsNotExist(err) {
		t.Fatal("expected bogus 1.27m folder removed")
	}

	// 4. Verify GET /api/workspace/search?q=admin_dump finds the file immediately!
	wSearch := req(http.MethodGet, "/api/workspace/search?q=admin_dump", "")
	if wSearch.Code != http.StatusOK || !strings.Contains(wSearch.Body.String(), "domains/inecnigeria.org/exfil/admin_dump.json") {
		t.Fatalf("GET /api/workspace/search?q=admin_dump failed: %d %s", wSearch.Code, wSearch.Body.String())
	}
}
