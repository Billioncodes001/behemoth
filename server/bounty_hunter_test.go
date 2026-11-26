package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/behemoth/db"
	"github.com/Autumn-27/behemoth/report"
)

func TestResetTokenUsageStatsPreservesFindingsAndTranscripts(t *testing.T) {
	m := proxyTestManager(t)
	s := &Server{m: m}

	// Record LLM usage ledger rows + conversation activity with token counts.
	if err := m.pg.InsertLLMUsage(&db.LLMUsage{
		TaskID:       "1",
		Worker:       "worker",
		Model:        "gpt-4o",
		ProfileName:  "Primary",
		InputTokens:  120000,
		OutputTokens: 4000,
		CacheRead:    80000,
		Status:       "ok",
	}); err != nil {
		t.Fatalf("InsertLLMUsage: %v", err)
	}

	conv, err := m.pg.CreateConversation("auto", "Keep My Chat", nil)
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	inTok, outTok := 50000, 1500
	if _, err := m.pg.AppendConvActivity(conv.ID, db.Activity{
		Worker:       "auto",
		Kind:         "result",
		Summary:      "Completed scan with critical finding preserved",
		InputTokens:  &inTok,
		OutputTokens: &outTok,
	}); err != nil {
		t.Fatalf("AppendConvActivity: %v", err)
	}

	// Call POST /api/tokens/reset
	req := httptest.NewRequest(http.MethodPost, "/api/tokens/reset", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	s.pgResetUsageStats(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from pgResetUsageStats, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify ledger is 0
	byProf, err := m.pg.UsageByProfile()
	if err != nil {
		t.Fatalf("UsageByProfile: %v", err)
	}
	if len(byProf) != 0 {
		t.Fatalf("expected 0 ledger profile buckets after reset, got %+v", byProf)
	}

	// Verify legacy conversation token summaries are 0 while the conversation activity row itself is preserved!
	summaries, err := m.pg.ConversationTokenSummaries()
	if err != nil {
		t.Fatalf("ConversationTokenSummaries: %v", err)
	}
	for _, sm := range summaries {
		if sm.InputTokens != 0 || sm.OutputTokens != 0 {
			t.Fatalf("expected conversation token counters zeroed, got %+v", sm)
		}
	}
	acts, _, err := m.pg.ConvActivityList(conv.ID, 0, 10)
	if err != nil || len(acts) == 0 || !strings.Contains(acts[0].Summary, "Completed scan") {
		t.Fatalf("expected conversation transcript preserved after token reset, got err=%v acts=%+v", err, acts)
	}
}

func TestBountyScoutAgentAndBountyFinderTrackerWorkflow(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)

	// 1. Verify built-in `bounty_scout` agent is seeded in PostgreSQL
	scout, err := s.m.pg.GetAgentByKey("bounty_scout")
	if err != nil || scout == nil {
		t.Fatalf("expected bounty_scout built-in agent seeded, got err=%v agent=%v", err, scout)
	}

	// 2. Register an open_direct (no-registration-needed) bug bounty program via native tool
	regIn, _ := json.Marshal(map[string]any{
		"name":                "Acme Cloud Bounty",
		"platform":            "self_hosted",
		"program_url":         "https://acme-bounty.example/security",
		"submission_url":      "https://acme-bounty.example/security/submit",
		"offers_bounty":       true,
		"min_bounty_usd":      250,
		"max_bounty_usd":      25000,
		"registration_type":   "open_direct",
		"registration_steps":  "No signup required — test *.acme-bounty.example and submit directly.",
		"safe_harbor":         true,
		"in_scope_targets":    []string{"*.acme-bounty.example", "https://api.acme-bounty.example"},
		"out_of_scope_targets": []string{"blog.acme-bounty.example"},
		"description":         "Direct cash bounty for Critical/High web & API flaws.",
	})
	regRes, err := s.toolRegisterBountyProgram().Call(context.Background(), regIn, nil)
	if err != nil || regRes.IsError {
		t.Fatalf("register_bounty_program failed: err=%v res=%s", err, regRes.Flatten())
	}
	var regOut struct {
		ProgramID int64 `json:"program_id"`
	}
	_ = json.Unmarshal([]byte(regRes.Content[0].Text), &regOut)
	if regOut.ProgramID <= 0 {
		t.Fatalf("expected valid program_id, got %s", regRes.Content[0].Text)
	}

	// 3. Start autonomous hunting via start_bounty_hunt -> enrolls scope, blocks out-of-scope host, creates Task, moves to Tracker
	huntIn, _ := json.Marshal(map[string]any{
		"program_id":   regOut.ProgramID,
		"custom_focus": "Focus on API authentication bypass and BOLA",
	})
	huntRes, err := s.toolStartBountyHunt().Call(context.Background(), huntIn, nil)
	if err != nil || huntRes.IsError {
		t.Fatalf("start_bounty_hunt failed: err=%v res=%s", err, huntRes.Flatten())
	}
	var huntOut struct {
		OK      bool             `json:"ok"`
		TaskID  string           `json:"task_id"`
		Program db.BountyProgram `json:"program"`
	}
	_ = json.Unmarshal([]byte(huntRes.Content[0].Text), &huntOut)
	if !huntOut.OK || huntOut.TaskID == "" || huntOut.Program.TrackerStatus != "hunting" || huntOut.Program.LinkedTaskID == nil {
		t.Fatalf("expected active hunting task linked, got %+v", huntOut)
	}

	// Verify out-of-scope exclusion rule was mechanically registered on the task!
	rules, err := s.m.Assets().ListTaskInterceptRules(*huntOut.Program.LinkedTaskID)
	if err != nil {
		t.Fatalf("ListTaskInterceptRules: %v", err)
	}
	foundBlock := false
	for _, r := range rules {
		if r.Action == "block" && strings.Contains(r.Pattern, "blog.acme-bounty.example") {
			foundBlock = true
			break
		}
	}
	if !foundBlock {
		t.Fatalf("expected task-scoped block rule for out-of-scope blog.acme-bounty.example, got %+v", rules)
	}

	// 4. Update tracker status to bug_found + earned payout
	updIn, _ := json.Marshal(map[string]any{
		"program_id":     regOut.ProgramID,
		"tracker_status": "rewarded",
		"earned_usd":     5000,
		"notes":          "Critical BOLA reported and rewarded $5,000",
	})
	updRes, err := s.toolUpdateBountyTracker().Call(context.Background(), updIn, nil)
	if err != nil || updRes.IsError {
		t.Fatalf("update_bounty_tracker failed: err=%v res=%s", err, updRes.Flatten())
	}

	summary, err := s.m.pg.GetBountyStatsSummary()
	if err != nil || summary.TotalEarnedUSD < 5000 || summary.NoRegistrationNeeded < 1 {
		t.Fatalf("unexpected bounty summary: %+v (err=%v)", summary, err)
	}
}

func TestBountyPlatformIsolationBinaryDeferralAndReportFormatting(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)

	prog := &db.BountyProgram{
		ProgramKey:    "bugcrowd:binance-test",
		Name:          "Binance",
		Platform:      "bugcrowd",
		ProgramURL:    "https://bugcrowd.com/engagements/binance",
		SubmissionURL: "https://bugcrowd.com/engagements/binance",
		OffersBounty:  true,
		MinBountyUSD:  0,
		MaxBountyUSD:  10000,
		Currency:      "USD",
		InScopeAssets: []db.BountyScopeAsset{
			{Target: "api.coinmarketcap.com", AssetType: "api", EligibleForBounty: true},
			{Target: "https://www.binance.com/", AssetType: "website", EligibleForBounty: true},
			{Target: "Trustwallet Chrome Extension", AssetType: "website", EligibleForBounty: true},
			{Target: "Binance Desktop Application", AssetType: "other", EligibleForBounty: true},
			{Target: "Binance Mobile Application for Android", AssetType: "android", EligibleForBounty: true},
		},
		InScopeCount: 5,
	}
	progID, _, err := s.m.pg.UpsertBountyProgram(prog)
	if err != nil || progID <= 0 {
		t.Fatalf("UpsertBountyProgram: err=%v id=%d", err, progID)
	}

	updatedProg, taskIDStr, err := s.startBountyHuntForProgram(context.Background(), progID, "", nil)
	if err != nil || updatedProg == nil || updatedProg.LinkedTaskID == nil {
		t.Fatalf("startBountyHuntForProgram failed: err=%v task=%s", err, taskIDStr)
	}
	tid := *updatedProg.LinkedTaskID
	taskObj, ok := s.m.Task(taskIDStr)
	if !ok || taskObj == nil {
		t.Fatalf("expected task %s in manager", taskIDStr)
	}

	// 1. Verify heavy desktop/mobile installers are deferred while Web/API/Chrome Extension stay primary!
	if !strings.Contains(taskObj.Goal, "Deferred Native/Mobile Binary Targets") || !strings.Contains(taskObj.Goal, "Trustwallet Chrome Extension") {
		t.Fatalf("expected binary deferral + Chrome Extension kept in scope, got Goal:\n%s", taskObj.Goal)
	}

	// 2. Verify bugcrowd.com was NEVER attached to Test Assets, and IS mechanically blocked!
	var bugcrowdLinked int
	_ = s.m.pg.QueryRow(`SELECT COUNT(*) FROM assets WHERE $1 = ANY(task_ids) AND LOWER(COALESCE(domain, '')) LIKE '%bugcrowd.com%'`, tid).Scan(&bugcrowdLinked)
	if bugcrowdLinked != 0 {
		t.Fatalf("expected 0 bugcrowd.com test assets linked to Task #%d, got %d", tid, bugcrowdLinked)
	}

	rules, err := s.m.Assets().ListTaskInterceptRules(tid)
	if err != nil {
		t.Fatalf("ListTaskInterceptRules: %v", err)
	}
	blockedBugcrowd := false
	for _, r := range rules {
		if r.Action == "block" && strings.Contains(r.Pattern, "bugcrowd.com") {
			blockedBugcrowd = true
			break
		}
	}
	if !blockedBugcrowd {
		t.Fatalf("expected task-scoped block rule protecting bugcrowd.com, got %+v", rules)
	}

	// 3. Simulate historical pollution (attaching bugcrowd.com to the task) and verify reconcileBountyTaskScopeIsolation detaches it while keeping binance.com!
	pollutedID, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: "bugcrowd.com", TaskID: tid})
	if err != nil || pollutedID <= 0 {
		t.Fatalf("UpsertRootDomain bugcrowd.com: %v", err)
	}
	_ = s.m.pg.SetSetting("bounty_scope_isolation_reconcile_v1", "")
	s.reconcileBountyTaskScopeIsolation()
	_ = s.m.pg.QueryRow(`SELECT COUNT(*) FROM assets WHERE $1 = ANY(task_ids) AND LOWER(COALESCE(domain, '')) LIKE '%bugcrowd.com%'`, tid).Scan(&bugcrowdLinked)
	if bugcrowdLinked != 0 {
		t.Fatalf("expected reconcileBountyTaskScopeIsolation to detach bugcrowd.com from Task #%d, still found %d", tid, bugcrowdLinked)
	}
	var binanceLinked int
	_ = s.m.pg.QueryRow(`SELECT COUNT(*) FROM assets WHERE $1 = ANY(task_ids) AND LOWER(COALESCE(domain, '')) LIKE '%binance.com%'`, tid).Scan(&binanceLinked)
	if binanceLinked == 0 {
		t.Fatalf("expected legitimate in-scope binance.com asset preserved on Task #%d", tid)
	}

	// 4. Verify Report Markdown renders multi-paragraph Goals under a clean Engagement Scope & Briefing section without breaking top metadata bullets!
	md := report.Markdown(report.Input{
		TaskID:      taskIDStr,
		Title:       "Bounty · Binance",
		Goal:        taskObj.Goal,
		Status:      "running",
		Scope:       []string{"api.coinmarketcap.com", "binance.com"},
		CreatedAt:   time.Now().Add(-15 * time.Minute),
		GeneratedAt: time.Now(),
	})
	if !strings.Contains(md, "### Engagement Scope & Briefing") || strings.Contains(md, "- **Primary Objective**: Autonomous Bug Bounty") {
		t.Fatalf("expected multi-line Goal rendered under Engagement Scope & Briefing section, got:\n%s", md[:min(len(md), 600)])
	}
}
