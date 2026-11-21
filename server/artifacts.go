package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Artifact (loot) storage. Every dump / text / screenshot / archive an agent
// saves lives under <dataDir>/artifacts and is indexed in the artifacts table so
// the Assets page can show it per company, per task and per asset.

const (
	maxArtifactBytes       = 256 << 20 // 256 MiB per artifact
	maxArtifactInlineBytes = 8 << 20   // inline text payload accepted by save_artifact
)

// artifactStore returns the artifact store, or nil without a database.
func (s *Server) artifactStore() *db.ArtifactStore {
	if s.m == nil || s.m.pg == nil {
		return nil
	}
	return s.m.pg.Artifacts()
}

// artifactsRoot is the directory holding every stored artifact file.
func (s *Server) artifactsRoot() string {
	return filepath.Join(s.dataDir, "artifacts")
}

// safeArtifactFilename reduces an arbitrary name to a portable single-segment
// filename that is safe on every OS.
func safeArtifactFilename(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_', r == ' ':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.ReplaceAll(strings.Trim(b.String(), "._-"), " ", "_")
	if len(out) > 120 {
		ext := filepath.Ext(out)
		base := strings.TrimSuffix(out, ext)
		if len(base) > 100 {
			base = base[:100]
		}
		out = base + ext
	}
	if out == "" {
		out = "artifact.bin"
	}
	return out
}

// artifactKindFor infers the artifact kind from the MIME type and filename.
func artifactKindFor(mimeType, filename string) string {
	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	ext := strings.ToLower(filepath.Ext(filename))
	switch {
	case strings.HasPrefix(mimeType, "image/"):
		return db.ArtifactKindImage
	case ext == ".sql" || ext == ".dump" || ext == ".bak" || ext == ".db" ||
		ext == ".sqlite" || ext == ".sqlite3" || ext == ".mdb" || ext == ".ndjson":
		return db.ArtifactKindDump
	case ext == ".zip" || ext == ".tar" || ext == ".gz" || ext == ".tgz" ||
		ext == ".bz2" || ext == ".xz" || ext == ".7z" || ext == ".rar":
		return db.ArtifactKindArchive
	case strings.HasPrefix(mimeType, "text/") || mimeType == "application/json" ||
		mimeType == "application/xml" || mimeType == "application/javascript":
		return db.ArtifactKindText
	case ext == ".txt" || ext == ".log" || ext == ".json" || ext == ".xml" ||
		ext == ".csv" || ext == ".html" || ext == ".htm" || ext == ".md" ||
		ext == ".yaml" || ext == ".yml" || ext == ".ini" || ext == ".conf":
		return db.ArtifactKindText
	case mimeType == "":
		return db.ArtifactKindOther
	}
	return db.ArtifactKindBinary
}

// guessArtifactMIME prefers the filename's declared type, then sniffs content.
func guessArtifactMIME(filename string, head []byte) string {
	if ext := filepath.Ext(filename); ext != "" {
		if t := mime.TypeByExtension(ext); t != "" {
			return t
		}
	}
	if len(head) > 0 {
		return http.DetectContentType(head)
	}
	return "application/octet-stream"
}

// artifactRelPath builds the on-disk relative path for a new artifact:
// c<company|0>/<yyyy>/<mm>/<sha12>-<filename>.
func artifactRelPath(companyID int64, sha, filename string, now time.Time) string {
	short := sha
	if len(short) > 12 {
		short = short[:12]
	}
	if short == "" {
		short = "nohash"
	}
	group := "c0"
	if companyID > 0 {
		group = fmt.Sprintf("c%d", companyID)
	}
	return path.Join(group, now.Format("2006"), now.Format("01"), short+"-"+filename)
}

// artifactAbsPath maps a stored rel_path back to an absolute path inside the
// artifacts root, rejecting traversal.
func (s *Server) artifactAbsPath(rel string) (string, error) {
	rel = strings.TrimSpace(strings.ReplaceAll(rel, "\\", "/"))
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") {
		return "", errors.New("invalid artifact path")
	}
	base := filepath.Clean(s.artifactsRoot())
	abs := filepath.Clean(filepath.Join(base, filepath.FromSlash(rel)))
	if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
		return "", errors.New("invalid artifact path")
	}
	return abs, nil
}

// resolveArtifactCompany picks the owning company: explicit id first, then the
// linked asset's owner, then a company_scope match on the source URL host.
func (s *Server) resolveArtifactCompany(explicit *int64, assetID *int64, sourceURL string) *int64 {
	if explicit != nil && *explicit > 0 {
		return explicit
	}
	if store := s.artifactStore(); store != nil && assetID != nil && *assetID > 0 {
		if cid, err := store.AssetCompany(*assetID); err == nil && cid != nil {
			return cid
		}
	}
	cs := s.companyStore()
	if cs == nil {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(sourceURL))
	if err != nil {
		return nil
	}
	host := u.Hostname()
	if host == "" {
		return nil
	}
	ip := ""
	if net.ParseIP(host) != nil {
		ip = host
	}
	if cid, err := cs.ResolveCompanyWithICP(host, ip, ""); err == nil && cid != nil {
		return cid
	}
	if root, apex := db.RootDomain(host); root != "" && (!apex || root != host) {
		if cid, err := cs.ResolveCompanyWithICP(root, ip, ""); err == nil && cid != nil {
			return cid
		}
	}
	return nil
}

// saveArtifact writes the bytes under the artifacts root (atomic rename) and
// indexes them. The file is removed again if the DB insert fails.
func (s *Server) saveArtifact(in artifactSaveInput) (*db.Artifact, error) {
	store := s.artifactStore()
	if store == nil {
		return nil, errors.New("database unavailable")
	}
	if len(in.Data) == 0 {
		return nil, errors.New("artifact content is empty")
	}
	if int64(len(in.Data)) > maxArtifactBytes {
		return nil, fmt.Errorf("artifact exceeds %d bytes", maxArtifactBytes)
	}
	sum := sha256.Sum256(in.Data)
	shaHex := hex.EncodeToString(sum[:])

	filename := safeArtifactFilename(firstNonEmpty(in.Filename, in.Name))
	mimeType := strings.TrimSpace(in.MIME)
	if mimeType == "" {
		head := in.Data
		if len(head) > 512 {
			head = head[:512]
		}
		mimeType = guessArtifactMIME(filename, head)
	}
	kind := strings.TrimSpace(in.Kind)
	if kind == "" {
		kind = artifactKindFor(mimeType, filename)
	}

	assetID := in.AssetID
	if (assetID == nil || *assetID <= 0) && strings.TrimSpace(in.SourceURL) != "" {
		if id, err := store.FindAssetByURL(in.SourceURL); err == nil && id > 0 {
			assetID = &id
		}
	}
	companyID := s.resolveArtifactCompany(in.CompanyID, assetID, in.SourceURL)

	now := time.Now().UTC()
	rel := artifactRelPath(derefInt64(companyID), shaHex, filename, now)
	abs, err := s.artifactAbsPath(rel)
	if err != nil {
		return nil, err
	}
	// Never overwrite an existing file: derive a unique suffix.
	for i := 1; ; i++ {
		if _, statErr := os.Stat(abs); errors.Is(statErr, os.ErrNotExist) {
			break
		}
		ext := filepath.Ext(filename)
		base := strings.TrimSuffix(filename, ext)
		rel = artifactRelPath(derefInt64(companyID), shaHex, fmt.Sprintf("%s-%d%s", base, i, ext), now)
		if abs, err = s.artifactAbsPath(rel); err != nil {
			return nil, err
		}
		if i > 50 {
			return nil, errors.New("could not allocate a unique artifact path")
		}
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return nil, err
	}
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, in.Data, 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}

	extra := in.Extra
	if extra == nil {
		extra = map[string]any{}
	}
	if _, ok := extra["saved_at"]; !ok {
		extra["saved_at"] = now.Format(time.RFC3339)
	}
	a, err := store.Create(db.ArtifactCreate{
		CompanyID:   companyID,
		TaskID:      in.TaskID,
		AssetID:     assetID,
		Name:        firstNonEmpty(in.Name, filename),
		Filename:    filename,
		RelPath:     rel,
		Kind:        kind,
		MIME:        mimeType,
		Size:        int64(len(in.Data)),
		SHA256:      shaHex,
		SourceURL:   strings.TrimSpace(in.SourceURL),
		SourceTool:  strings.TrimSpace(in.SourceTool),
		Description: strings.TrimSpace(in.Description),
		Extra:       extra,
	})
	if err != nil {
		_ = os.Remove(abs)
		return nil, err
	}
	return a, nil
}

// artifactFilterFromQuery parses the shared list filters.
func artifactFilterFromQuery(r *http.Request) db.ArtifactFilter {
	q := r.URL.Query()
	f := db.ArtifactFilter{
		Kind:  q.Get("kind"),
		Query: q.Get("q"),
	}
	if v, err := strconv.ParseInt(q.Get("company_id"), 10, 64); err == nil && v > 0 {
		f.CompanyID = v
	}
	if v, err := strconv.ParseInt(q.Get("task_id"), 10, 64); err == nil && v > 0 {
		f.TaskID = v
	}
	if v, err := strconv.ParseInt(q.Get("asset_id"), 10, 64); err == nil && v > 0 {
		f.AssetID = v
	}
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		f.Limit = v
	}
	if v, err := strconv.Atoi(q.Get("offset")); err == nil && v > 0 {
		f.Offset = v
	}
	return f
}

// artifactSaveInput is everything needed to persist one artifact.
type artifactSaveInput struct {
	Name        string
	Filename    string
	Kind        string
	MIME        string
	SourceURL   string
	SourceTool  string
	Description string
	CompanyID   *int64
	TaskID      *int64
	AssetID     *int64
	Extra       map[string]any
	Data        []byte
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// GET /api/artifacts — one page of artifacts + per-kind counts for the tab badge.
func (s *Server) listArtifacts(w http.ResponseWriter, r *http.Request) {
	as := s.artifactStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	f := artifactFilterFromQuery(r)
	items, total, err := as.List(f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	counts, err := as.Counts(f.CompanyID, f.TaskID)
	if err != nil {
		counts = map[string]int{"total": total}
	}
	writeJSON(w, 200, map[string]any{"artifacts": items, "total": total, "counts": counts})
}

// GET /api/artifacts/counts — per-kind + total artifact counts for tab badges.
func (s *Server) artifactCounts(w http.ResponseWriter, r *http.Request) {
	as := s.artifactStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	f := artifactFilterFromQuery(r)
	counts, err := as.Counts(f.CompanyID, f.TaskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, counts)
}

// GET /api/artifacts/{id} — metadata only.
func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	as := s.artifactStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid artifact id")
		return
	}
	a, err := as.Get(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "artifact not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, a)
}

// GET /api/artifacts/{id}/download?inline=1 — stream the stored bytes.
func (s *Server) serveArtifact(w http.ResponseWriter, r *http.Request) {
	as := s.artifactStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid artifact id")
		return
	}
	a, err := as.Get(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "artifact not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	abs, err := s.artifactAbsPath(a.RelPath)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		writeErr(w, 404, "artifact file missing")
		return
	}
	defer f.Close()
	name := sanitizeFilename(firstNonEmpty(a.Filename, a.Name))
	disposition := "attachment"
	if r.URL.Query().Get("inline") == "1" {
		disposition = "inline"
	}
	setFileDisposition(w, disposition, name)
	w.Header().Set("Content-Type", firstNonEmpty(a.MIME, "application/octet-stream"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	http.ServeContent(w, r, name, time.Now(), f)
}

// DELETE /api/artifacts/{id} — removes the row and the stored file.
func (s *Server) deleteArtifact(w http.ResponseWriter, r *http.Request) {
	as := s.artifactStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid artifact id")
		return
	}
	a, err := as.Delete(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "artifact not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if abs, perr := s.artifactAbsPath(a.RelPath); perr == nil {
		_ = os.Remove(abs)
	}
	writeJSON(w, 200, map[string]any{"deleted": 1})
}

// POST /api/artifacts — manual upload from the UI (multipart field "file").
func (s *Server) uploadArtifact(w http.ResponseWriter, r *http.Request) {
	if s.artifactStore() == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxArtifactBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "parse upload failed: "+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "missing upload file (form field file)")
		return
	}
	companyID := parseOptionalID(r.FormValue("company_id"))
	taskID := parseOptionalID(r.FormValue("task_id"))
	assetID := parseOptionalID(r.FormValue("asset_id"))
	out := make([]*db.Artifact, 0, len(files))
	var firstErr string
	for _, hdr := range files {
		f, err := hdr.Open()
		if err != nil {
			firstErr = err.Error()
			continue
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			firstErr = err.Error()
			continue
		}
		a, err := s.saveArtifact(artifactSaveInput{
			Name:        firstNonEmpty(r.FormValue("name"), hdr.Filename),
			Filename:    hdr.Filename,
			Kind:        r.FormValue("kind"),
			SourceURL:   r.FormValue("source_url"),
			Description: r.FormValue("description"),
			CompanyID:   companyID,
			TaskID:      taskID,
			AssetID:     assetID,
			Data:        data,
		})
		if err != nil {
			firstErr = err.Error()
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 && firstErr != "" {
		writeErr(w, 500, firstErr)
		return
	}
	writeJSON(w, 200, map[string]any{"artifacts": out, "errors": firstErr})
}

// parseOptionalID parses an optional positive integer form/query value.
func parseOptionalID(raw string) *int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || v <= 0 {
		return nil
	}
	return &v
}
