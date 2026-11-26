package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const bountySchemaSQL = `
CREATE TABLE IF NOT EXISTS bounty_programs (
    id                      BIGSERIAL PRIMARY KEY,
    program_key             TEXT NOT NULL UNIQUE,
    name                    TEXT NOT NULL,
    platform                TEXT NOT NULL DEFAULT 'self_hosted',
    program_url             TEXT NOT NULL,
    submission_url          TEXT NOT NULL DEFAULT '',
    offers_bounty           BOOLEAN NOT NULL DEFAULT true,
    min_bounty_usd          DOUBLE PRECISION NOT NULL DEFAULT 0,
    max_bounty_usd          DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency                TEXT NOT NULL DEFAULT 'USD',
    registration_type       TEXT NOT NULL DEFAULT 'free_platform_account',
    registration_steps      TEXT NOT NULL DEFAULT '',
    safe_harbor             BOOLEAN NOT NULL DEFAULT false,
    in_scope_assets         JSONB NOT NULL DEFAULT '[]'::jsonb,
    out_of_scope_assets     JSONB NOT NULL DEFAULT '[]'::jsonb,
    in_scope_count          INTEGER NOT NULL DEFAULT 0,
    description             TEXT NOT NULL DEFAULT '',
    focus_vulns             TEXT NOT NULL DEFAULT '',
    tracker_status          TEXT NOT NULL DEFAULT 'discovered',
    linked_task_id          BIGINT,
    linked_conversation_id  BIGINT,
    earned_usd              DOUBLE PRECISION NOT NULL DEFAULT 0,
    submission_notes        TEXT NOT NULL DEFAULT '',
    source_feed             TEXT NOT NULL DEFAULT '',
    discovered_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_hunting_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_bounty_programs_tracker ON bounty_programs(tracker_status);
CREATE INDEX IF NOT EXISTS idx_bounty_programs_platform ON bounty_programs(platform);
CREATE INDEX IF NOT EXISTS idx_bounty_programs_payout ON bounty_programs(max_bounty_usd DESC);
`

// BountyScopeAsset describes one in-scope or out-of-scope asset entry of a bug bounty program.
type BountyScopeAsset struct {
	Target            string `json:"target"`
	AssetType         string `json:"asset_type,omitempty"`
	EligibleForBounty bool   `json:"eligible_for_bounty,omitempty"`
	MaxSeverity       string `json:"max_severity,omitempty"`
	Instruction       string `json:"instruction,omitempty"`
}

// BountyProgram represents a discovered or actively tracked bug bounty program.
type BountyProgram struct {
	ID                   int64              `json:"id"`
	ProgramKey           string             `json:"program_key"`
	Name                 string             `json:"name"`
	Platform             string             `json:"platform"`
	ProgramURL           string             `json:"program_url"`
	SubmissionURL        string             `json:"submission_url"`
	OffersBounty         bool               `json:"offers_bounty"`
	MinBountyUSD         float64            `json:"min_bounty_usd"`
	MaxBountyUSD         float64            `json:"max_bounty_usd"`
	Currency             string             `json:"currency"`
	RegistrationType     string             `json:"registration_type"` // "open_direct" | "free_platform_account" | "application_or_kyc"
	RegistrationSteps    string             `json:"registration_steps"`
	SafeHarbor           bool               `json:"safe_harbor"`
	InScopeAssets        []BountyScopeAsset `json:"in_scope_assets"`
	OutOfScopeAssets     []BountyScopeAsset `json:"out_of_scope_assets"`
	InScopeCount         int                `json:"in_scope_count"`
	Description          string             `json:"description"`
	FocusVulns           string             `json:"focus_vulns"`
	TrackerStatus        string             `json:"tracker_status"` // "discovered" | "hunting" | "paused" | "bug_found" | "submitted" | "triaged" | "rewarded" | "archived"
	LinkedTaskID         *int64             `json:"linked_task_id,omitempty"`
	LinkedConversationID *int64             `json:"linked_conversation_id,omitempty"`
	EarnedUSD            float64            `json:"earned_usd"`
	SubmissionNotes      string             `json:"submission_notes"`
	SourceFeed           string             `json:"source_feed"`
	DiscoveredAt         time.Time          `json:"discovered_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
	StartedHuntingAt     *time.Time         `json:"started_hunting_at,omitempty"`
}

// BountyProgramFilter filters bounty program listings.
type BountyProgramFilter struct {
	Query            string
	Platform         string
	RegistrationType string
	TrackerOnly      bool
	FinderOnly       bool
	PaidOnly         bool
	SortBy           string // "payout" | "scope" | "newest" | "updated"
	Limit            int
}

func (d *DB) EnsureBountyTables() error {
	_, err := d.Exec(bountySchemaSQL)
	return err
}

// UpsertBountyProgram inserts or refreshes a discovered bug bounty program while
// preserving operator tracker state (tracker_status, linked_task_id, earned_usd, notes).
func (d *DB) UpsertBountyProgram(p *BountyProgram) (id int64, newlyInserted bool, err error) {
	if p == nil || strings.TrimSpace(p.ProgramKey) == "" || strings.TrimSpace(p.Name) == "" {
		return 0, false, fmt.Errorf("program_key and name are required")
	}
	inJSON, _ := json.Marshal(p.InScopeAssets)
	if len(inJSON) == 0 || string(inJSON) == "null" {
		inJSON = []byte("[]")
	}
	outJSON, _ := json.Marshal(p.OutOfScopeAssets)
	if len(outJSON) == 0 || string(outJSON) == "null" {
		outJSON = []byte("[]")
	}
	inCount := len(p.InScopeAssets)
	if p.InScopeCount > inCount {
		inCount = p.InScopeCount
	}
	platform := strings.ToLower(strings.TrimSpace(p.Platform))
	if platform == "" {
		platform = "self_hosted"
	}
	regType := strings.ToLower(strings.TrimSpace(p.RegistrationType))
	if regType == "" {
		regType = "free_platform_account"
	}
	currency := strings.ToUpper(strings.TrimSpace(p.Currency))
	if currency == "" {
		currency = "USD"
	}
	trackerStatus := strings.ToLower(strings.TrimSpace(p.TrackerStatus))
	if trackerStatus == "" {
		trackerStatus = "discovered"
	}

	var xmax uint64
	err = d.QueryRow(`
INSERT INTO bounty_programs (
    program_key, name, platform, program_url, submission_url,
    offers_bounty, min_bounty_usd, max_bounty_usd, currency,
    registration_type, registration_steps, safe_harbor,
    in_scope_assets, out_of_scope_assets, in_scope_count,
    description, focus_vulns, tracker_status, source_feed, updated_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12,
    $13::jsonb, $14::jsonb, $15,
    $16, $17, $18, $19, now()
)
ON CONFLICT (program_key) DO UPDATE SET
    name               = EXCLUDED.name,
    platform           = EXCLUDED.platform,
    program_url        = EXCLUDED.program_url,
    submission_url     = CASE WHEN EXCLUDED.submission_url <> '' THEN EXCLUDED.submission_url ELSE bounty_programs.submission_url END,
    offers_bounty      = EXCLUDED.offers_bounty,
    min_bounty_usd     = CASE WHEN EXCLUDED.min_bounty_usd > 0 THEN EXCLUDED.min_bounty_usd ELSE bounty_programs.min_bounty_usd END,
    max_bounty_usd     = CASE WHEN EXCLUDED.max_bounty_usd > 0 THEN EXCLUDED.max_bounty_usd ELSE bounty_programs.max_bounty_usd END,
    currency           = EXCLUDED.currency,
    registration_type  = EXCLUDED.registration_type,
    registration_steps = CASE WHEN EXCLUDED.registration_steps <> '' THEN EXCLUDED.registration_steps ELSE bounty_programs.registration_steps END,
    safe_harbor        = EXCLUDED.safe_harbor OR bounty_programs.safe_harbor,
    in_scope_assets    = CASE WHEN jsonb_array_length(EXCLUDED.in_scope_assets) > 0 THEN EXCLUDED.in_scope_assets ELSE bounty_programs.in_scope_assets END,
    out_of_scope_assets= CASE WHEN jsonb_array_length(EXCLUDED.out_of_scope_assets) > 0 THEN EXCLUDED.out_of_scope_assets ELSE bounty_programs.out_of_scope_assets END,
    in_scope_count     = GREATEST(EXCLUDED.in_scope_count, bounty_programs.in_scope_count),
    description        = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE bounty_programs.description END,
    focus_vulns        = CASE WHEN EXCLUDED.focus_vulns <> '' THEN EXCLUDED.focus_vulns ELSE bounty_programs.focus_vulns END,
    source_feed        = CASE WHEN EXCLUDED.source_feed <> '' THEN EXCLUDED.source_feed ELSE bounty_programs.source_feed END,
    updated_at         = now()
RETURNING id, (xmax::text::bigint)`,
		strings.TrimSpace(p.ProgramKey), strings.TrimSpace(p.Name), platform,
		strings.TrimSpace(p.ProgramURL), strings.TrimSpace(p.SubmissionURL),
		p.OffersBounty, p.MinBountyUSD, p.MaxBountyUSD, currency,
		regType, strings.TrimSpace(p.RegistrationSteps), p.SafeHarbor,
		string(inJSON), string(outJSON), inCount,
		strings.TrimSpace(p.Description), strings.TrimSpace(p.FocusVulns),
		trackerStatus, strings.TrimSpace(p.SourceFeed),
	).Scan(&id, &xmax)
	if err != nil {
		return 0, false, err
	}
	return id, xmax == 0, nil
}

func scanBountyRow(scanner interface{ Scan(...any) error }) (*BountyProgram, error) {
	var p BountyProgram
	var inRaw, outRaw []byte
	var taskID, convID sql.NullInt64
	var startedAt sql.NullTime
	err := scanner.Scan(
		&p.ID, &p.ProgramKey, &p.Name, &p.Platform, &p.ProgramURL, &p.SubmissionURL,
		&p.OffersBounty, &p.MinBountyUSD, &p.MaxBountyUSD, &p.Currency,
		&p.RegistrationType, &p.RegistrationSteps, &p.SafeHarbor,
		&inRaw, &outRaw, &p.InScopeCount,
		&p.Description, &p.FocusVulns, &p.TrackerStatus,
		&taskID, &convID, &p.EarnedUSD, &p.SubmissionNotes,
		&p.SourceFeed, &p.DiscoveredAt, &p.UpdatedAt, &startedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(inRaw) > 0 {
		_ = json.Unmarshal(inRaw, &p.InScopeAssets)
	}
	if p.InScopeAssets == nil {
		p.InScopeAssets = []BountyScopeAsset{}
	}
	if len(outRaw) > 0 {
		_ = json.Unmarshal(outRaw, &p.OutOfScopeAssets)
	}
	if p.OutOfScopeAssets == nil {
		p.OutOfScopeAssets = []BountyScopeAsset{}
	}
	if taskID.Valid {
		v := taskID.Int64
		p.LinkedTaskID = &v
	}
	if convID.Valid {
		v := convID.Int64
		p.LinkedConversationID = &v
	}
	if startedAt.Valid {
		t := startedAt.Time
		p.StartedHuntingAt = &t
	}
	return &p, nil
}

const bountySelectCols = `
    id, program_key, name, platform, program_url, submission_url,
    offers_bounty, min_bounty_usd, max_bounty_usd, currency,
    registration_type, registration_steps, safe_harbor,
    in_scope_assets, out_of_scope_assets, in_scope_count,
    description, focus_vulns, tracker_status,
    linked_task_id, linked_conversation_id, earned_usd, submission_notes,
    source_feed, discovered_at, updated_at, started_hunting_at`

func (d *DB) GetBountyProgram(id int64) (*BountyProgram, error) {
	row := d.QueryRow(`SELECT `+bountySelectCols+` FROM bounty_programs WHERE id = $1`, id)
	p, err := scanBountyRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

func (d *DB) ListBountyPrograms(f BountyProgramFilter) ([]*BountyProgram, error) {
	var conds []string
	var args []any
	addArg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if f.TrackerOnly {
		conds = append(conds, "tracker_status <> 'discovered' AND tracker_status <> 'archived'")
	} else if f.FinderOnly {
		conds = append(conds, "tracker_status <> 'archived'")
	}
	if f.PaidOnly {
		conds = append(conds, "offers_bounty = true")
	}
	if plat := strings.ToLower(strings.TrimSpace(f.Platform)); plat != "" && plat != "all" {
		conds = append(conds, "platform = "+addArg(plat))
	}
	if reg := strings.ToLower(strings.TrimSpace(f.RegistrationType)); reg != "" && reg != "all" {
		conds = append(conds, "registration_type = "+addArg(reg))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		pat := "%" + strings.ToLower(q) + "%"
		ph := addArg(pat)
		conds = append(conds, fmt.Sprintf("(LOWER(name) LIKE %s OR LOWER(program_url) LIKE %s OR LOWER(description) LIKE %s OR LOWER(in_scope_assets::text) LIKE %s)", ph, ph, ph, ph))
	}

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	orderBy := " ORDER BY max_bounty_usd DESC, in_scope_count DESC, discovered_at DESC"
	switch strings.ToLower(strings.TrimSpace(f.SortBy)) {
	case "scope":
		orderBy = " ORDER BY in_scope_count DESC, max_bounty_usd DESC"
	case "newest":
		orderBy = " ORDER BY discovered_at DESC, id DESC"
	case "updated":
		orderBy = " ORDER BY updated_at DESC, id DESC"
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 250
	}
	limitSQL := fmt.Sprintf(" LIMIT %d", limit)

	rows, err := d.Query(`SELECT `+bountySelectCols+` FROM bounty_programs`+where+orderBy+limitSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*BountyProgram{}
	for rows.Next() {
		p, serr := scanBountyRow(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateBountyTracking updates tracker status, linked task/conversation, payout earned, or notes.
func (d *DB) UpdateBountyTracking(id int64, status *string, taskID *int64, convID *int64, earnedUSD *float64, submissionURL *string, notes *string) (*BountyProgram, error) {
	cur, err := d.GetBountyProgram(id)
	if err != nil || cur == nil {
		return cur, err
	}
	st := cur.TrackerStatus
	if status != nil && strings.TrimSpace(*status) != "" {
		st = strings.ToLower(strings.TrimSpace(*status))
	}
	tid := cur.LinkedTaskID
	if taskID != nil {
		if *taskID <= 0 {
			tid = nil
		} else {
			tid = taskID
		}
	}
	cid := cur.LinkedConversationID
	if convID != nil {
		if *convID <= 0 {
			cid = nil
		} else {
			cid = convID
		}
	}
	earned := cur.EarnedUSD
	if earnedUSD != nil {
		earned = *earnedUSD
	}
	subURL := cur.SubmissionURL
	if submissionURL != nil {
		subURL = strings.TrimSpace(*submissionURL)
	}
	noteVal := cur.SubmissionNotes
	if notes != nil {
		noteVal = strings.TrimSpace(*notes)
	}

	var startedAt any = cur.StartedHuntingAt
	if st == "hunting" && cur.StartedHuntingAt == nil {
		now := time.Now()
		startedAt = now
	}

	_, err = d.Exec(`
UPDATE bounty_programs
SET tracker_status = $2,
    linked_task_id = $3,
    linked_conversation_id = $4,
    earned_usd = $5,
    submission_notes = $6,
    submission_url = $7,
    started_hunting_at = $8,
    updated_at = now()
WHERE id = $1`,
		id, st, tid, cid, earned, noteVal, subURL, startedAt)
	if err != nil {
		return nil, err
	}
	return d.GetBountyProgram(id)
}

func (d *DB) DeleteBountyProgram(id int64) error {
	_, err := d.Exec(`DELETE FROM bounty_programs WHERE id = $1`, id)
	return err
}

// BountyStatsSummary returns top-level KPI metrics across all bounty programs.
type BountyStatsSummary struct {
	TotalDiscovered      int     `json:"total_discovered"`
	PaidPrograms         int     `json:"paid_programs"`
	NoRegistrationNeeded int     `json:"no_registration_needed"`
	ActivelyHunting      int     `json:"actively_hunting"`
	BugsFoundReady       int     `json:"bugs_found_ready"`
	SubmittedOrRewarded  int     `json:"submitted_or_rewarded"`
	TotalEarnedUSD       float64 `json:"total_earned_usd"`
}

func (d *DB) GetBountyStatsSummary() (BountyStatsSummary, error) {
	var s BountyStatsSummary
	err := d.QueryRow(`
SELECT
    COUNT(*) FILTER (WHERE tracker_status <> 'archived'),
    COUNT(*) FILTER (WHERE offers_bounty = true AND tracker_status <> 'archived'),
    COUNT(*) FILTER (WHERE registration_type = 'open_direct' AND tracker_status <> 'archived'),
    COUNT(*) FILTER (WHERE tracker_status = 'hunting'),
    COUNT(*) FILTER (WHERE tracker_status = 'bug_found'),
    COUNT(*) FILTER (WHERE tracker_status IN ('submitted', 'triaged', 'rewarded')),
    COALESCE(SUM(earned_usd), 0)
FROM bounty_programs`).Scan(
		&s.TotalDiscovered,
		&s.PaidPrograms,
		&s.NoRegistrationNeeded,
		&s.ActivelyHunting,
		&s.BugsFoundReady,
		&s.SubmittedOrRewarded,
		&s.TotalEarnedUSD,
	)
	return s, err
}
