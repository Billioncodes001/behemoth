package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPatchArsenalSynergyUpdateFindingAndBrowserMCPChromiumArgs(t *testing.T) {
	// 1. Verify ensureBrowserMCPArgs always injects --browser chromium and --ignore-https-errors
	args := ensureBrowserMCPArgs([]string{"@playwright/mcp"}, true)
	joinedArgs := strings.Join(args, " ")
	for _, want := range []string{"--headless", "--no-sandbox", "--browser chromium", "--ignore-https-errors", "--isolated"} {
		if !strings.Contains(joinedArgs, want) {
			t.Fatalf("expected %q in ensureBrowserMCPArgs, got: %v", want, args)
		}
	}

	s, initial, _ := trafficEvidenceServer(t)

	// 2. Verify update_finding escalates Low -> Medium, sets status='confirmed', and appends PoC evidence
	updIn, _ := json.Marshal(map[string]any{
		"finding_id":      initial.FindingID,
		"severity":        "medium",
		"status":          "confirmed",
		"name":            "Outdated Client-Side Libraries — Exploited Origin XSS",
		"summary":         "Live DOM XSS execution verified across jQuery 3.2.1 (CISA KEV CVE-2020-11023) and Bootstrap 4.0.0-beta.",
		"append_evidence": "jQuery(div).html('<style/><img src=x onerror=\"window.__ab=1\">') -> executed on live origin",
	})
	updRes, err := s.toolUpdateFinding().Call(context.Background(), updIn, nil)
	if err != nil || updRes.IsError {
		t.Fatalf("update_finding failed: err=%v res=%s", err, updRes.Flatten())
	}
	fAfter, err := s.m.pg.GetFinding(initial.FindingID)
	if err != nil || fAfter == nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if fAfter.Severity != "medium" || fAfter.Status != "confirmed" || !strings.Contains(fAfter.Evidence, "window.__ab=1") {
		t.Fatalf("expected finding escalated to medium/confirmed with appended PoC, got: %+v", fAfter)
	}

	// 3. Verify two-way Patch Monitor Arsenal synergy:
	//    Agent saves verified working jQuery 3.2.1 PoC via save_verified_exploit_to_patch_monitor,
	//    and next agent immediately finds it via search_patch_arsenal!
	saveIn, _ := json.Marshal(map[string]any{
		"cve_id":            "CVE-2020-11022",
		"title":             "jQuery < 3.5.0 htmlPrefilter Self-Closing Style XSS PoC",
		"code":              `jQuery(div).html('<style/><img src=x onerror="window.__xss=1">');`,
		"language":          "javascript",
		"exploit_type":      "xss",
		"severity":          "medium",
		"cvss_score":        6.9,
		"affected_software": "jQuery",
		"affected_versions": "1.2 - 3.4.1",
		"patched_version":   "3.5.0",
		"verified_target":   "https://tax-database.oirs.ng",
		"verified_output":   "window.__xss === 1 verified in headless Chromium",
	})
	saveRes, err := s.toolSaveVerifiedExploitToPatchMonitor().Call(context.Background(), saveIn, nil)
	if err != nil || saveRes.IsError || !strings.Contains(saveRes.Flatten(), "verified_working") {
		t.Fatalf("save_verified_exploit_to_patch_monitor failed: err=%v res=%s", err, saveRes.Flatten())
	}

	searchRes, err := s.toolSearchPatchArsenal().Call(context.Background(), json.RawMessage(`{"query":"jQuery"}`), nil)
	if err != nil || searchRes.IsError {
		t.Fatalf("search_patch_arsenal failed: err=%v res=%s", err, searchRes.Flatten())
	}
	flat := searchRes.Flatten()
	if !strings.Contains(flat, "CVE-2020-11022") || !strings.Contains(flat, "window.__xss=1") || !strings.Contains(flat, "verified_working") {
		t.Fatalf("expected search_patch_arsenal to return saved working jQuery PoC, got: %s", flat)
	}
}
