package db

import (
	"database/sql"
	"strings"
	"time"
)

const taskChatLinksSchemaSQL = `
CREATE TABLE IF NOT EXISTS task_chat_links (
    task_id                BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    conversation_id        BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    agent_key              TEXT NOT NULL DEFAULT 'auto',
    notified_goals_ready   BOOLEAN NOT NULL DEFAULT false,
    last_finding_id        BIGINT NOT NULL DEFAULT 0,
    last_status_notified   TEXT NOT NULL DEFAULT '',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, conversation_id)
);

CREATE INDEX IF NOT EXISTS idx_task_chat_links_conv ON task_chat_links(conversation_id);
`

// TaskChatLink binds a background multi-agent Task to the /chat conversation
// that spawned or steered it so live milestone, finding, and completion updates
// automatically post back into that chat thread.
type TaskChatLink struct {
	TaskID             int64
	ConversationID     int64
	AgentKey           string
	NotifiedGoalsReady bool
	LastFindingID      int64
	LastStatusNotified string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (d *DB) EnsureTaskChatLinksTables() error {
	_, err := d.Exec(taskChatLinksSchemaSQL)
	return err
}

// MaxFindingIDForTask returns the current highest standalone finding ID for taskID
// (0 if none exist yet). Used when linking an already-running task to a new chat
// so only subsequent findings stream into that chat.
func (d *DB) MaxFindingIDForTask(taskID int64) (int64, error) {
	var maxID sql.NullInt64
	err := d.QueryRow(`SELECT MAX(id) FROM findings WHERE task_id = $1`, taskID).Scan(&maxID)
	if err != nil {
		return 0, err
	}
	if !maxID.Valid {
		return 0, nil
	}
	return maxID.Int64, nil
}

// UpsertTaskChatLink links taskID <-> conversationID idempotently. If the link
// already exists, its existing watermarks are preserved.
func (d *DB) UpsertTaskChatLink(taskID, conversationID int64, agentKey string, baselineFindingID int64) error {
	if taskID <= 0 || conversationID <= 0 {
		return nil
	}
	ag := strings.TrimSpace(agentKey)
	if ag == "" {
		ag = "auto"
	}
	_, err := d.Exec(`
		INSERT INTO task_chat_links (task_id, conversation_id, agent_key, last_finding_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (task_id, conversation_id) DO UPDATE
		SET updated_at = now()
	`, taskID, conversationID, ag, baselineFindingID)
	return err
}

// ResetTaskChatTerminalState clears last_status_notified when a terminal task
// is revived or resumed for follow-up work so its next completion posts a fresh
// wrap-up back into linked chats.
func (d *DB) ResetTaskChatTerminalState(taskID int64) error {
	if taskID <= 0 {
		return nil
	}
	_, err := d.Exec(`
		UPDATE task_chat_links
		SET last_status_notified = '', updated_at = now()
		WHERE task_id = $1 AND last_status_notified <> ''
	`, taskID)
	return err
}

func scanTaskChatLinks(rows *sql.Rows, err error) ([]TaskChatLink, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskChatLink
	for rows.Next() {
		var r TaskChatLink
		if err := rows.Scan(
			&r.TaskID,
			&r.ConversationID,
			&r.AgentKey,
			&r.NotifiedGoalsReady,
			&r.LastFindingID,
			&r.LastStatusNotified,
			&r.CreatedAt,
			&r.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) ListTaskChatLinks() ([]TaskChatLink, error) {
	return scanTaskChatLinks(d.Query(`
		SELECT l.task_id, l.conversation_id, l.agent_key, l.notified_goals_ready,
		       l.last_finding_id, l.last_status_notified, l.created_at, l.updated_at
		FROM task_chat_links l
		JOIN tasks t ON t.id = l.task_id AND t.deleted_at IS NULL
		ORDER BY l.task_id ASC, l.conversation_id ASC
	`))
}

func (d *DB) ListTaskChatLinksByTask(taskID int64) ([]TaskChatLink, error) {
	return scanTaskChatLinks(d.Query(`
		SELECT l.task_id, l.conversation_id, l.agent_key, l.notified_goals_ready,
		       l.last_finding_id, l.last_status_notified, l.created_at, l.updated_at
		FROM task_chat_links l
		JOIN tasks t ON t.id = l.task_id AND t.deleted_at IS NULL
		WHERE l.task_id = $1
		ORDER BY l.conversation_id ASC
	`, taskID))
}

func (d *DB) ListTaskChatLinksByConversation(conversationID int64) ([]TaskChatLink, error) {
	return scanTaskChatLinks(d.Query(`
		SELECT l.task_id, l.conversation_id, l.agent_key, l.notified_goals_ready,
		       l.last_finding_id, l.last_status_notified, l.created_at, l.updated_at
		FROM task_chat_links l
		JOIN tasks t ON t.id = l.task_id AND t.deleted_at IS NULL
		WHERE l.conversation_id = $1
		ORDER BY l.updated_at DESC, l.task_id DESC
	`, conversationID))
}

// MarkTaskChatGoalsNotified atomically flips notified_goals_ready from false -> true
// and returns won=true only for the first caller.
func (d *DB) MarkTaskChatGoalsNotified(taskID, conversationID int64) (bool, error) {
	res, err := d.Exec(`
		UPDATE task_chat_links
		SET notified_goals_ready = true, updated_at = now()
		WHERE task_id = $1 AND conversation_id = $2 AND notified_goals_ready = false
	`, taskID, conversationID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *DB) AdvanceTaskChatFindingWatermark(taskID, conversationID, findingID int64) error {
	_, err := d.Exec(`
		UPDATE task_chat_links
		SET last_finding_id = GREATEST(last_finding_id, $3), updated_at = now()
		WHERE task_id = $1 AND conversation_id = $2
	`, taskID, conversationID, findingID)
	return err
}

// MarkTaskChatStatusNotified atomically records status on (task_id, conversation_id)
// if it differs from last_status_notified, returning won=true only once per status transition.
func (d *DB) MarkTaskChatStatusNotified(taskID, conversationID int64, status string) (bool, error) {
	st := strings.TrimSpace(status)
	if st == "" {
		return false, nil
	}
	res, err := d.Exec(`
		UPDATE task_chat_links
		SET last_status_notified = $3, updated_at = now()
		WHERE task_id = $1 AND conversation_id = $2 AND last_status_notified <> $3
	`, taskID, conversationID, st)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListTaskFindingsAfter returns non-false-positive findings for taskID with id > afterID
// ordered oldest-first so chat updates stream in exact chronological discovery order.
func (d *DB) ListTaskFindingsAfter(taskID, afterID int64) ([]*DBFinding, error) {
	rows, err := d.Query(`
		SELECT id, task_id, node_id, COALESCE(vulnclass, ''), COALESCE(name, ''),
		       COALESCE(severity, 'medium'), COALESCE(summary, ''), COALESCE(worker, ''),
		       COALESCE(status, 'pending'), created_at
		FROM findings
		WHERE task_id = $1
		  AND id > $2
		  AND COALESCE(status, '') NOT IN ('false_positive', 'duplicate', 'ignored')
		ORDER BY id ASC
	`, taskID, afterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DBFinding
	for rows.Next() {
		f := &DBFinding{}
		var tid, nid sql.NullInt64
		if err := rows.Scan(&f.ID, &tid, &nid, &f.VulnClass, &f.Name, &f.Severity, &f.Summary, &f.Worker, &f.Status, &f.CreatedAt); err != nil {
			return nil, err
		}
		if tid.Valid {
			v := tid.Int64
			f.TaskID = &v
		}
		if nid.Valid {
			v := nid.Int64
			f.NodeID = &v
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
