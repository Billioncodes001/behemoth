package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// =====================================================================
// Agent capability requests (report_need)
// Agents report missing tools/capabilities/infra during tasks; operators
// review and triage them on System → Agent Requests. Same shape as the
// artifacts store: filterable List + per-status Counts for badges.
// =====================================================================

// Agent request kinds. The DB enforces the same set with a CHECK constraint
// (kept in sync by EnsureAgentRequestKinds on existing databases).
const (
	AgentRequestKindTool        = "tool"
	AgentRequestKindToolError   = "tool_error"
	AgentRequestKindResource    = "resource"
	AgentRequestKindCapability  = "capability"
	AgentRequestKindIntegration = "integration"
	AgentRequestKindInfra       = "infra"
	AgentRequestKindData        = "data"
	AgentRequestKindOther       = "other"
)

// AgentRequestKinds is the ordered list of valid kinds (for validation + UI).
var AgentRequestKinds = []string{
	AgentRequestKindTool, AgentRequestKindToolError, AgentRequestKindResource,
	AgentRequestKindCapability, AgentRequestKindIntegration,
	AgentRequestKindInfra, AgentRequestKindData, AgentRequestKindOther,
}

// Agent request urgencies.
const (
	AgentRequestUrgencyLow    = "low"
	AgentRequestUrgencyNormal = "normal"
	AgentRequestUrgencyHigh   = "high"
)

// AgentRequestUrgencies is the ordered list of valid urgencies.
var AgentRequestUrgencies = []string{
	AgentRequestUrgencyLow, AgentRequestUrgencyNormal, AgentRequestUrgencyHigh,
}

// Agent request lifecycle statuses.
const (
	AgentRequestStatusNew          = "new"
	AgentRequestStatusAcknowledged = "acknowledged"
	AgentRequestStatusResolved     = "resolved"
	AgentRequestStatusDismissed    = "dismissed"
)

// AgentRequestStatuses is the ordered list of valid statuses.
var AgentRequestStatuses = []string{
	AgentRequestStatusNew, AgentRequestStatusAcknowledged,
	AgentRequestStatusResolved, AgentRequestStatusDismissed,
}

// AgentRequest is a row in the agent_requests table: one reported need.
type AgentRequest struct {
	ID        int64          `json:"id"`
	AgentKey  string         `json:"agent_key"`
	TaskID    *int64         `json:"task_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	Kind      string         `json:"kind"`
	Urgency   string         `json:"urgency"`
	Title     string         `json:"title"`
	Details   string         `json:"details,omitempty"`
	Context   string         `json:"context,omitempty"`
	Status    string         `json:"status"`
	Extra     map[string]any `json:"extra,omitempty"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
}

// AgentRequestCreate is the insert payload.
type AgentRequestCreate struct {
	AgentKey  string
	TaskID    *int64
	SessionID string
	Kind      string
	Urgency   string
	Title     string
	Details   string
	Context   string
	Extra     map[string]any
}

// AgentRequestFilter scopes List. Zero values mean "no filter".
type AgentRequestFilter struct {
	Status string
	Kind   string
	Agent  string
	TaskID int64
	Query  string // substring match on title/details/context/agent_key
	Limit  int
	Offset int
}

// AgentRequestStore operates on the agent_requests table.
type AgentRequestStore struct{ db *DB }

// AgentRequests returns the agent request store.
func (d *DB) AgentRequests() *AgentRequestStore { return &AgentRequestStore{db: d} }

// NormalizeAgentRequestKind returns a valid kind, defaulting to capability.
func NormalizeAgentRequestKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	for _, k := range AgentRequestKinds {
		if k == kind {
			return k
		}
	}
	return AgentRequestKindCapability
}

// NormalizeAgentRequestUrgency returns a valid urgency, defaulting to normal.
func NormalizeAgentRequestUrgency(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	for _, v := range AgentRequestUrgencies {
		if v == u {
			return v
		}
	}
	return AgentRequestUrgencyNormal
}

// ValidAgentRequestStatus reports whether status is one of the lifecycle values.
func ValidAgentRequestStatus(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	for _, v := range AgentRequestStatuses {
		if v == status {
			return true
		}
	}
	return false
}

const agentRequestColumns = `r.id, r.agent_key, r.task_id, r.session_id, r.kind,
	r.urgency, r.title, r.details, r.context, r.status, r.extra,
	r.created_at::text, r.updated_at::text`

// agentRequestReturningCols is the unqualified column list for INSERT ...
// RETURNING: the INSERT target has no "r" alias, so the r.-prefixed SELECT list
// above cannot be reused there.
const agentRequestReturningCols = `id, agent_key, task_id, session_id, kind,
	urgency, title, details, context, status, extra,
	created_at::text, updated_at::text`

func scanAgentRequest(sc interface{ Scan(...any) error }) (*AgentRequest, error) {
	var (
		r        AgentRequest
		taskID   sql.NullInt64
		extraRaw []byte
	)
	if err := sc.Scan(
		&r.ID, &r.AgentKey, &taskID, &r.SessionID, &r.Kind,
		&r.Urgency, &r.Title, &r.Details, &r.Context, &r.Status, &extraRaw,
		&r.CreatedAt, &r.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if taskID.Valid {
		v := taskID.Int64
		r.TaskID = &v
	}
	if len(extraRaw) > 0 {
		_ = json.Unmarshal(extraRaw, &r.Extra)
	}
	return &r, nil
}

// Create inserts one agent request row and returns it (with timestamps).
func (s *AgentRequestStore) Create(req AgentRequestCreate) (*AgentRequest, error) {
	title := strings.TrimSpace(req.Title)
	if title == "" {
		return nil, fmt.Errorf("agent request title is required")
	}
	extra := req.Extra
	if extra == nil {
		extra = map[string]any{}
	}
	extraJSON, err := json.Marshal(extra)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRow(`
INSERT INTO agent_requests (agent_key, task_id, session_id, kind, urgency,
                            title, details, context, extra)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
RETURNING `+agentRequestReturningCols,
		strings.TrimSpace(req.AgentKey), req.TaskID, strings.TrimSpace(req.SessionID),
		NormalizeAgentRequestKind(req.Kind), NormalizeAgentRequestUrgency(req.Urgency),
		title, strings.TrimSpace(req.Details), strings.TrimSpace(req.Context), extraJSON)
	return scanAgentRequest(row)
}

// agentRequestWhere builds the shared WHERE clause for List.
func agentRequestWhere(f AgentRequestFilter) (string, []any) {
	var clauses []string
	var args []any
	add := func(clause string, v any) {
		args = append(args, v)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if st := strings.TrimSpace(f.Status); st != "" && ValidAgentRequestStatus(st) {
		add("r.status = $%d", st)
	}
	if k := strings.TrimSpace(f.Kind); k != "" {
		add("r.kind = $%d", NormalizeAgentRequestKind(k))
	}
	if a := strings.TrimSpace(f.Agent); a != "" {
		add("r.agent_key = $%d", a)
	}
	if f.TaskID > 0 {
		add("r.task_id = $%d", f.TaskID)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+q+"%")
		n := len(args)
		// Same placeholder reused across the OR branches.
		clauses = append(clauses, fmt.Sprintf(
			"(r.title ILIKE $%d OR r.details ILIKE $%d OR r.context ILIKE $%d OR r.agent_key ILIKE $%d)",
			n, n, n, n))
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// List returns one page of agent requests plus the filtered total.
func (s *AgentRequestStore) List(f AgentRequestFilter) ([]*AgentRequest, int, error) {
	where, args := agentRequestWhere(f)
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM agent_requests r`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.db.Query(fmt.Sprintf(`
SELECT %s FROM agent_requests r%s
ORDER BY r.created_at DESC, r.id DESC
LIMIT $%d OFFSET $%d`, agentRequestColumns, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*AgentRequest, 0, limit)
	for rows.Next() {
		r, err := scanAgentRequest(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// Get loads one agent request by id.
func (s *AgentRequestStore) Get(id int64) (*AgentRequest, error) {
	row := s.db.QueryRow(`SELECT `+agentRequestColumns+` FROM agent_requests r WHERE r.id = $1`, id)
	return scanAgentRequest(row)
}

// SetStatus moves one request through the lifecycle (new → acknowledged →
// resolved / dismissed) and returns the updated row.
func (s *AgentRequestStore) SetStatus(id int64, status string) (*AgentRequest, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	if !ValidAgentRequestStatus(status) {
		return nil, fmt.Errorf("invalid agent request status %q", status)
	}
	row := s.db.QueryRow(`
UPDATE agent_requests r SET status = $2 WHERE r.id = $1
RETURNING `+agentRequestColumns, id, status)
	return scanAgentRequest(row)
}

// Delete removes one request row and returns the deleted record.
func (s *AgentRequestStore) Delete(id int64) (*AgentRequest, error) {
	row := s.db.QueryRow(`DELETE FROM agent_requests r WHERE r.id = $1 RETURNING `+agentRequestColumns, id)
	return scanAgentRequest(row)
}

// Counts returns the request count per status plus "total", so the UI can
// badge every lifecycle tab and the top-bar alerts bell in one query.
func (s *AgentRequestStore) Counts() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT status, COUNT(*) FROM agent_requests GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{"total": 0}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
		out["total"] += n
	}
	return out, rows.Err()
}

// agentRequestKindCheckNames is the set of kinds the agent_requests.kind CHECK
// constraint must allow. Older databases carry a narrower constraint (before
// tool_error/resource were added), which would silently coerce the new kinds
// back to "capability" — so the constraint is recreated idempotently on startup.
func agentRequestKindCheckNames() string {
	quoted := make([]string, 0, len(AgentRequestKinds))
	for _, k := range AgentRequestKinds {
		quoted = append(quoted, "'"+k+"'")
	}
	return strings.Join(quoted, ",")
}

// EnsureAgentRequestKinds recreates the agent_requests.kind CHECK constraint so
// it matches AgentRequestKinds. Safe to run on every startup.
func (d *DB) EnsureAgentRequestKinds() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`ALTER TABLE agent_requests DROP CONSTRAINT IF EXISTS agent_requests_kind_check`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE agent_requests ADD CONSTRAINT agent_requests_kind_check CHECK (kind IN (` +
		agentRequestKindCheckNames() + `))`); err != nil {
		return err
	}
	return tx.Commit()
}
