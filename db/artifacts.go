package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// =====================================================================
// 战利品文件库 (artifacts)
// =====================================================================

// Artifact kinds. The DB enforces the same set with a CHECK constraint.
const (
	ArtifactKindText    = "text"
	ArtifactKindImage   = "image"
	ArtifactKindDump    = "dump"
	ArtifactKindArchive = "archive"
	ArtifactKindBinary  = "binary"
	ArtifactKindOther   = "other"
)

// ArtifactKinds is the ordered list of valid kinds (for validation + UI).
var ArtifactKinds = []string{
	ArtifactKindText, ArtifactKindImage, ArtifactKindDump,
	ArtifactKindArchive, ArtifactKindBinary, ArtifactKindOther,
}

// Artifact is a row in the artifacts table: one stored file (dump, text,
// screenshot, archive…) with its provenance.
type Artifact struct {
	ID          int64          `json:"id"`
	CompanyID   *int64         `json:"company_id,omitempty"`
	TaskID      *int64         `json:"task_id,omitempty"`
	AssetID     *int64         `json:"asset_id,omitempty"`
	Name        string         `json:"name"`
	Filename    string         `json:"filename"`
	RelPath     string         `json:"rel_path"`
	Kind        string         `json:"kind"`
	MIME        string         `json:"mime,omitempty"`
	Size        int64          `json:"size"`
	SHA256      string         `json:"sha256,omitempty"`
	SourceURL   string         `json:"source_url,omitempty"`
	SourceTool  string         `json:"source_tool,omitempty"`
	Description string         `json:"description,omitempty"`
	Extra       map[string]any `json:"extra,omitempty"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at"`
}

// ArtifactCreate is the insert payload.
type ArtifactCreate struct {
	CompanyID   *int64
	TaskID      *int64
	AssetID     *int64
	Name        string
	Filename    string
	RelPath     string
	Kind        string
	MIME        string
	Size        int64
	SHA256      string
	SourceURL   string
	SourceTool  string
	Description string
	Extra       map[string]any
}

// ArtifactFilter scopes List/Counts. Zero values mean "no filter".
type ArtifactFilter struct {
	CompanyID int64
	TaskID    int64
	AssetID   int64
	Kind      string
	Query     string // substring match on name/filename/source_url/description
	Limit     int
	Offset    int
}

// ArtifactStore operates on the artifacts table.
type ArtifactStore struct{ db *DB }

// Artifacts returns the artifact store.
func (d *DB) Artifacts() *ArtifactStore { return &ArtifactStore{db: d} }

// NormalizeArtifactKind returns a valid kind, defaulting to other.
func NormalizeArtifactKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	for _, k := range ArtifactKinds {
		if k == kind {
			return k
		}
	}
	return ArtifactKindOther
}

const artifactColumns = `a.id, a.company_id, a.task_id, a.asset_id, a.name, a.filename,
	a.rel_path, a.kind, a.mime, a.size, a.sha256, a.source_url, a.source_tool,
	a.description, a.extra, a.created_at::text, a.updated_at::text`

// artifactReturningCols is the unqualified column list for INSERT ... RETURNING
// (the INSERT target carries no "a" alias).
const artifactReturningCols = `id, company_id, task_id, asset_id, name, filename,
	rel_path, kind, mime, size, sha256, source_url, source_tool,
	description, extra, created_at::text, updated_at::text`

func scanArtifact(sc interface{ Scan(...any) error }) (*Artifact, error) {
	var (
		a                 Artifact
		companyID, taskID sql.NullInt64
		assetID           sql.NullInt64
		extraRaw          []byte
	)
	if err := sc.Scan(
		&a.ID, &companyID, &taskID, &assetID, &a.Name, &a.Filename,
		&a.RelPath, &a.Kind, &a.MIME, &a.Size, &a.SHA256, &a.SourceURL,
		&a.SourceTool, &a.Description, &extraRaw, &a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if companyID.Valid {
		v := companyID.Int64
		a.CompanyID = &v
	}
	if taskID.Valid {
		v := taskID.Int64
		a.TaskID = &v
	}
	if assetID.Valid {
		v := assetID.Int64
		a.AssetID = &v
	}
	if len(extraRaw) > 0 {
		_ = json.Unmarshal(extraRaw, &a.Extra)
	}
	return &a, nil
}

// Create inserts one artifact row and returns it (with timestamps).
func (s *ArtifactStore) Create(req ArtifactCreate) (*Artifact, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSpace(req.Filename)
	}
	if name == "" {
		return nil, fmt.Errorf("artifact name is required")
	}
	relPath := strings.TrimSpace(req.RelPath)
	if relPath == "" {
		return nil, fmt.Errorf("artifact rel_path is required")
	}
	kind := NormalizeArtifactKind(req.Kind)
	extra := req.Extra
	if extra == nil {
		extra = map[string]any{}
	}
	extraJSON, err := json.Marshal(extra)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRow(`
INSERT INTO artifacts (company_id, task_id, asset_id, name, filename, rel_path,
                       kind, mime, size, sha256, source_url, source_tool, description, extra)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
RETURNING `+artifactReturningCols,
		req.CompanyID, req.TaskID, req.AssetID, name, strings.TrimSpace(req.Filename), relPath,
		kind, strings.TrimSpace(req.MIME), req.Size, strings.TrimSpace(req.SHA256),
		strings.TrimSpace(req.SourceURL), strings.TrimSpace(req.SourceTool),
		strings.TrimSpace(req.Description), extraJSON)
	return scanArtifact(row)
}

// artifactWhere builds the shared WHERE clause for List/Counts.
func artifactWhere(f ArtifactFilter) (string, []any) {
	var clauses []string
	var args []any
	add := func(clause string, v any) {
		args = append(args, v)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if f.CompanyID > 0 {
		add("a.company_id = $%d", f.CompanyID)
	}
	if f.TaskID > 0 {
		add("a.task_id = $%d", f.TaskID)
	}
	if f.AssetID > 0 {
		add("a.asset_id = $%d", f.AssetID)
	}
	if kind := strings.TrimSpace(f.Kind); kind != "" {
		add("a.kind = $%d", strings.ToLower(kind))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+q+"%")
		n := len(args)
		// Same placeholder reused across the OR branches.
		clauses = append(clauses, fmt.Sprintf(
			"(a.name ILIKE $%d OR a.filename ILIKE $%d OR a.source_url ILIKE $%d OR a.description ILIKE $%d)",
			n, n, n, n))
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// List returns one page of artifacts plus the filtered total.
func (s *ArtifactStore) List(f ArtifactFilter) ([]*Artifact, int, error) {
	where, args := artifactWhere(f)
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
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM artifacts a`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.db.Query(fmt.Sprintf(`
SELECT %s FROM artifacts a%s
ORDER BY a.created_at DESC, a.id DESC
LIMIT $%d OFFSET $%d`, artifactColumns, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*Artifact, 0, limit)
	for rows.Next() {
		a, err := scanArtifact(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// Get loads one artifact by id.
func (s *ArtifactStore) Get(id int64) (*Artifact, error) {
	row := s.db.QueryRow(`SELECT `+artifactColumns+` FROM artifacts a WHERE a.id = $1`, id)
	return scanArtifact(row)
}

// Delete removes one artifact row and returns the deleted record so the caller
// can also remove the file from disk.
func (s *ArtifactStore) Delete(id int64) (*Artifact, error) {
	row := s.db.QueryRow(`DELETE FROM artifacts a WHERE a.id = $1 RETURNING `+artifactColumns, id)
	return scanArtifact(row)
}

// Counts returns the artifact count per kind plus "total", optionally scoped.
func (s *ArtifactStore) Counts(companyID, taskID int64) (map[string]int, error) {
	f := ArtifactFilter{CompanyID: companyID, TaskID: taskID}
	where, args := artifactWhere(f)
	rows, err := s.db.Query(`SELECT a.kind, COUNT(*) FROM artifacts a`+where+` GROUP BY a.kind`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{"total": 0}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, err
		}
		out[kind] = n
		out["total"] += n
	}
	return out, rows.Err()
}

// AssetCompany returns the owning company of an asset (nil when unattributed).
func (s *ArtifactStore) AssetCompany(assetID int64) (*int64, error) {
	if assetID <= 0 {
		return nil, nil
	}
	var cid sql.NullInt64
	err := s.db.QueryRow(`SELECT company_id FROM assets WHERE id = $1`, assetID).Scan(&cid)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !cid.Valid {
		return nil, nil
	}
	v := cid.Int64
	return &v, nil
}

// FindAssetByURL returns the most recent service/endpoint asset id for a URL,
// used to link a saved artifact back to the exact asset it came from.
func (s *ArtifactStore) FindAssetByURL(rawURL string) (int64, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return 0, nil
	}
	var id int64
	err := s.db.QueryRow(`
SELECT id FROM assets
WHERE url = $1 AND type IN ('service','endpoint')
ORDER BY last_seen DESC, id DESC
LIMIT 1`, rawURL).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}
