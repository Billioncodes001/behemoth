package server

import (
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Workspace file manager — browse / view / edit / download / upload / delete the
// shared work dir (s.m.dir), where all agents write their artifacts. Every path is
// confined to the work dir root (traversal via ".." is neutralised). All routes sit
// behind requireAuth (see Handler()).

const (
	maxWorkspaceRead   = 2 << 20   // 2 MiB: files bigger than this aren't inlined for view/edit (download instead)
	maxWorkspaceUpload = 512 << 20 // 512 MiB per upload request
)

// wsCanonicalBase resolves symlinks on the workspace root itself (e.g. macOS /var -> /private/var)
// so symlink containment checks compare canonical paths accurately.
func (s *Server) wsCanonicalBase() string {
	base := filepath.Clean(s.m.dir)
	if realBase, err := filepath.EvalSymlinks(base); err == nil && realBase != "" {
		return filepath.Clean(realBase)
	}
	return base
}

// wsContainsResolved verifies that p (and its deepest existing ancestor on disk)
// resolves via EvalSymlinks to a location strictly inside the workspace root.
// Internal workspace symlinks (such as sessions/conv-N/<domain> -> domains/<domain>)
// remain allowed, while any symlink pointing outside s.m.dir is rejected.
func (s *Server) wsContainsResolved(abs string) bool {
	realBase := s.wsCanonicalBase()
	cur := filepath.Clean(abs)
	var suffix []string
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			cand := filepath.Clean(resolved)
			for i := len(suffix) - 1; i >= 0; i-- {
				cand = filepath.Join(cand, suffix[i])
			}
			cand = filepath.Clean(cand)
			return cand == realBase || strings.HasPrefix(cand, realBase+string(os.PathSeparator))
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false
		}
		suffix = append(suffix, filepath.Base(cur))
		cur = parent
	}
}

// wsResolve maps a user-supplied relative path to an absolute path INSIDE the work
// dir. It returns ok=false if the path (or any symlink along it) would escape the root.
func (s *Server) wsResolve(rel string) (string, bool) {
	if s == nil || s.m == nil || strings.TrimSpace(s.m.dir) == "" {
		return "", false
	}
	base := filepath.Clean(s.m.dir)
	rel = strings.TrimPrefix(strings.TrimSpace(rel), "/")
	clean := filepath.Clean("/" + rel) // e.g. "/a/../../etc" → "/etc" (still rooted at "/")
	abs := filepath.Clean(filepath.Join(base, clean))
	if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
		return "", false
	}
	if !s.wsContainsResolved(abs) {
		return "", false
	}
	return abs, true
}

// wsRel renders an absolute path back as a workspace-relative path (forward slashes).
func (s *Server) wsRel(abs string) string {
	base := filepath.Clean(s.m.dir)
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}

var (
	reURLDomainExtract  = regexp.MustCompile(`(?i)https?://([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+|\d{1,3}(?:\.\d{1,3}){3})`)
	reBareDomainExtract = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b`)
	reDomainishName     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	nonDomainExts       = map[string]bool{
		"html": true, "htm": true, "json": true, "txt": true, "md": true, "py": true,
		"js": true, "ts": true, "tsx": true, "css": true, "php": true, "sql": true,
		"sh": true, "yaml": true, "yml": true, "xml": true, "csv": true, "zip": true,
		"png": true, "jpg": true, "jpeg": true, "svg": true, "pdf": true, "log": true,
	}
)

// baseDomainSuffixes lists common two-label public suffixes (multi-part TLDs)
// so e.g. portal.uniosun.edu.ng collapses to uniosun.edu.ng, not edu.ng.
var baseDomainSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true,
	"com.br": true, "com.mx": true, "com.ar": true, "com.co": true, "com.pe": true, "com.uy": true,
	"com.eg": true, "com.ng": true, "edu.ng": true, "gov.ng": true, "org.ng": true, "net.ng": true, "sch.ng": true, "ac.ng": true, "co.ng": true,
	"com.gh": true, "com.ke": true, "co.ke": true, "co.tz": true,
	"co.za": true, "org.za": true, "com.zm": true,
	"co.in": true, "net.in": true, "org.in": true, "edu.in": true, "gov.in": true,
	"com.pk": true, "com.bd": true, "com.lk": true,
	"com.my": true, "com.sg": true, "co.id": true, "com.ph": true, "com.vn": true, "co.th": true,
	"com.hk": true, "com.tw": true, "com.cn": true, "gov.cn": true, "edu.cn": true, "org.cn": true, "net.cn": true,
	"com.tr": true, "com.sa": true, "com.ae": true, "com.qa": true, "com.kw": true, "com.bh": true, "com.om": true,
	"com.ua": true, "com.ru": true, "co.kr": true, "or.kr": true, "co.il": true,
	"com.es": true, "com.pt": true, "com.pl": true, "com.gr": true, "com.ro": true, "com.cz": true,
	"co.ca": true, "com.de": true, "com.fr": true, "com.it": true, "com.nl": true, "com.se": true, "com.no": true,
}

// baseDomainOf reduces a hostname to its registrable base domain (eTLD+1),
// handling multi-part suffixes like .edu.ng / .co.uk. IPs and single-label
// hosts pass through unchanged.
func baseDomainOf(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" || !strings.Contains(h, ".") {
		return h
	}
	if ip := net.ParseIP(h); ip != nil {
		return h
	}
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	last2 := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if baseDomainSuffixes[last2] {
		return parts[len(parts)-3] + "." + last2
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// extractPrimaryTargetDomain pulls a clean target domain/host (e.g. "tax-database.oirs.ng")
// out of a prompt, task description, or conversation title.
func extractPrimaryTargetDomain(text string) string {
	if m := reURLDomainExtract.FindStringSubmatch(text); len(m) >= 2 {
		h := strings.ToLower(strings.TrimSpace(m[1]))
		if u, err := url.Parse("http://" + h); err == nil && u.Hostname() != "" {
			h = u.Hostname()
		}
		if h != "localhost" && h != "127.0.0.1" && h != "github.com" {
			return h
		}
	}
	for _, m := range reBareDomainExtract.FindAllStringSubmatch(text, 10) {
		cand := strings.ToLower(strings.TrimSpace(m[1]))
		parts := strings.Split(cand, ".")
		tld := parts[len(parts)-1]
		if len(tld) < 2 || nonDomainExts[tld] {
			continue
		}
		if cand == "localhost" || strings.HasSuffix(cand, ".internal") || cand == "github.com" {
			continue
		}
		return cand
	}
	return ""
}

// ensureDomainWorkspaceStructure creates `<workDir>/domains/<domain>/` with standard
// subfolders (`portal-simulation`, `evidence`) and optionally links it inside sessionDir
// so target artifacts, CREDENTIALS.md, and simulated HTML portals are organized by domain!
func (s *Server) ensureDomainWorkspaceStructure(domain, sessionID string) {
	if s == nil || s.m == nil || strings.TrimSpace(s.m.dir) == "" || domain == "" {
		return
	}
	safeDom := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			return r
		}
		return -1
	}, strings.ToLower(strings.TrimSpace(domain)))
	if safeDom == "" || strings.HasPrefix(safeDom, ".") {
		return
	}
	domDir := filepath.Join(s.m.dir, "domains", safeDom)
	_ = os.MkdirAll(filepath.Join(domDir, "portal-simulation"), 0o755)
	_ = os.MkdirAll(filepath.Join(domDir, "evidence"), 0o755)
	credPath := filepath.Join(domDir, "CREDENTIALS.md")
	if _, err := os.Stat(credPath); os.IsNotExist(err) {
		header := fmt.Sprintf("# Portal & Account Credentials — `%s`\n\n| Portal Login URL | Username / Email | Password / Token | Role / Access Level | Source (Created / Found) | Login Steps & Verification |\n|---|---|---|---|---|---|\n", safeDom)
		_ = os.WriteFile(credPath, []byte(header), 0o644)
	}
	if sessionID != "" {
		sessDir := filepath.Join(s.m.dir, "sessions", sessionID)
		_ = os.MkdirAll(sessDir, 0o755)
		linkPath := filepath.Join(sessDir, safeDom)
		if _, err := os.Lstat(linkPath); os.IsNotExist(err) {
			_ = os.Symlink(domDir, linkPath)
		}
	}
}

// sessionDirDomain inspects a session directory for domain-scoped workspace
// links (sessions/conv-N/<domain> → domains/<domain>, created by
// ensureDomainWorkspaceStructure) or domain-named subfolders, returning the
// most recently modified candidate domain ("" when none).
func (s *Server) sessionDirDomain(sessAbs string) string {
	ents, err := os.ReadDir(sessAbs)
	if err != nil {
		return ""
	}
	domainsDir := filepath.Join(filepath.Clean(s.m.dir), "domains") + string(os.PathSeparator)
	best := ""
	var bestMod int64
	for _, e := range ents {
		full := filepath.Join(sessAbs, e.Name())
		lstat, err := os.Lstat(full)
		if err != nil {
			continue
		}
		info, serr := os.Stat(full) // follow internal symlinks
		if serr != nil {
			info = lstat
		}
		cand := ""
		if lstat.Mode()&os.ModeSymlink != 0 {
			if target, terr := os.Readlink(full); terr == nil {
				t := filepath.Clean(target)
				if filepath.IsAbs(t) && strings.HasPrefix(t, domainsDir) {
					cand = filepath.Base(t)
				}
			}
		}
		if cand == "" && info.IsDir() && reDomainishName.MatchString(strings.ToLower(e.Name())) {
			cand = strings.ToLower(e.Name())
		}
		if cand == "" {
			continue
		}
		mod := info.ModTime().UnixNano()
		if best == "" || mod > bestMod {
			best, bestMod = cand, mod
		}
	}
	return best
}

// conversationMessageDomain extracts a target domain from the conversation's
// first user message — the usual place a target URL appears when the title
// itself doesn't carry one. Activity lists omit the lazy detail blob, so the
// first user activity's detail is loaded explicitly.
func (s *Server) conversationMessageDomain(convID int64) string {
	acts, _, err := s.m.pg.ConvActivityList(convID, 0, 10)
	if err != nil {
		return ""
	}
	for _, a := range acts {
		if a.Kind != "user" {
			continue
		}
		if dom := extractPrimaryTargetDomain(a.Summary); dom != "" {
			return dom
		}
		if detail, derr := s.m.pg.ConvActivityDetail(convID, a.ID); derr == nil {
			if dom := extractPrimaryTargetDomain(detail); dom != "" {
				return dom
			}
		}
		return "" // only the first user message is a reliable target hint
	}
	return ""
}

func classifyWorkspaceKind(name string, isDir bool) string {
	if isDir {
		return "Folder"
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "credential") {
		return "Credentials"
	}
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
	switch ext {
	case "html", "htm":
		return "Portal HTML"
	case "md":
		return "Markdown"
	case "json":
		return "JSON"
	case "py":
		return "Python"
	case "js", "mjs", "ts":
		return "Script"
	case "sql":
		return "SQL"
	case "txt", "log":
		return "Text"
	case "csv":
		return "CSV"
	case "png", "jpg", "jpeg", "webp", "svg":
		return "Image"
	case "pdf":
		return "PDF"
	case "yaml", "yml":
		return "YAML"
	default:
		if ext != "" {
			return strings.ToUpper(ext)
		}
		return "File"
	}
}

type wsEntry struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Kind        string `json:"kind"`
	Path        string `json:"path"`
	Dir         bool   `json:"dir"`
	Size        int64  `json:"size"`
	MTime       int64  `json:"mtime"` // unix millis
}

// GET /api/workspace/list?path=<rel>
func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "Invalid path")
		return
	}
	if abs == filepath.Clean(s.m.dir) {
		_ = os.MkdirAll(abs, 0o755)
		_ = os.MkdirAll(filepath.Join(abs, "domains"), 0o755)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		writeErr(w, 404, "Path does not exist")
		return
	}
	if !fi.IsDir() {
		writeErr(w, 400, "Not a directory")
		return
	}
	ents, err := os.ReadDir(abs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	relDir := s.wsRel(abs)
	out := make([]wsEntry, 0, len(ents))
	for _, e := range ents {
		fullEntryPath := filepath.Join(abs, e.Name())
		if !s.wsContainsResolved(fullEntryPath) {
			continue
		}
		info, err := os.Stat(fullEntryPath) // follow internal symlinks (e.g. session -> domains/<domain>)
		if err != nil {
			info, err = e.Info()
			if err != nil {
				continue
			}
		}
		isDir := info.IsDir()
		displayName := ""
		if isDir && relDir == "sessions" && strings.HasPrefix(e.Name(), "conv-") && s.m != nil && s.m.pg != nil {
			if cid, perr := strconv.ParseInt(strings.TrimPrefix(e.Name(), "conv-"), 10, 64); perr == nil {
				if conv, cerr := s.m.pg.GetConversation(cid); cerr == nil && conv != nil {
					// Label sessions by the BASE DOMAIN they worked on — resolved
					// from the conversation title, then the domain-scoped
					// workspace links inside the session dir, then the first
					// user message — so related sessions cluster visually
					// instead of showing arbitrary conversation text.
					dom := extractPrimaryTargetDomain(conv.Title)
					if dom == "" {
						dom = s.sessionDirDomain(filepath.Join(abs, e.Name()))
					}
					if dom == "" {
						dom = s.conversationMessageDomain(cid)
					}
					if dom != "" {
						displayName = fmt.Sprintf("%s (%s)", baseDomainOf(dom), e.Name())
					} else if strings.TrimSpace(conv.Title) != "" {
						displayName = fmt.Sprintf("%s (%s)", strings.TrimSpace(conv.Title), e.Name())
					}
				}
			}
		} else if isDir && relDir == "tasks" && s.m != nil {
			if t, ok := s.m.Task(e.Name()); ok && t != nil {
				dom := extractPrimaryTargetDomain(t.Name + " " + t.Description + " " + t.Goal)
				label := strings.TrimSpace(t.Name)
				if dom != "" {
					displayName = fmt.Sprintf("%s (Task #%s)", baseDomainOf(dom), e.Name())
				} else if label != "" {
					displayName = fmt.Sprintf("%s (Task #%s)", label, e.Name())
				}
			}
		}

		out = append(out, wsEntry{
			Name:        e.Name(),
			DisplayName: displayName,
			Kind:        classifyWorkspaceKind(e.Name(), isDir),
			Path:        s.wsRel(fullEntryPath),
			Dir:         isDir,
			Size:        info.Size(),
			MTime:       info.ModTime().UnixMilli(),
		})
	}
	// Default server order: directories first, then newest modified first!
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return out[i].MTime > out[j].MTime
	})
	writeJSON(w, 200, map[string]any{"path": relDir, "entries": out})
}

// GET /api/workspace/read?path=<rel> — inline text for view/edit. Binary or oversize
// files return {binary:true}/{too_large:true} with no content (use download instead).
func (s *Server) wsRead(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "Invalid path")
		return
	}
	fi, err := os.Stat(abs)
	if err != nil {
		writeErr(w, 404, "File does not exist")
		return
	}
	if fi.IsDir() {
		writeErr(w, 400, "Target is a directory and cannot be read as a file")
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer f.Close()
	writeTextFile(w, s.wsRel(abs), f, fi.Size())
}

// POST /api/workspace/write  {path, content} — create/overwrite a text file.
func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "Invalid path")
		return
	}
	if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
		writeErr(w, 400, "Target is a directory")
		return
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := os.WriteFile(abs, []byte(req.Content), 0o644); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// POST /api/workspace/mkdir  {path}
func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "Invalid path")
		return
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// DELETE /api/workspace/delete?path=<rel> — removes a file or a directory tree
// (confined to the work dir; the root itself can't be deleted).
func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "Invalid path")
		return
	}
	if abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "Cannot delete workspace root directory")
		return
	}
	if _, err := os.Stat(abs); err != nil {
		writeErr(w, 404, "Path does not exist")
		return
	}
	if err := os.RemoveAll(abs); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/workspace/download?path=<rel> — stream a file as an attachment.
func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "Invalid path")
		return
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		writeErr(w, 404, "File does not exist")
		return
	}
	name := filepath.Base(abs)
	// RFC 5987 filename* keeps non-ASCII names intact; plain filename is the fallback.
	setFileDisposition(w, "attachment", name)
	http.ServeFile(w, r, abs)
}

// GET /api/workspace/preview?path=<rel> — serve an image inline for report
// Markdown. Unlike download, this uses an inline content disposition so a
// report can render a saved browser screenshot with a normal Markdown image URL.
func (s *Server) wsPreview(w http.ResponseWriter, r *http.Request) {
	rawPath := strings.TrimSpace(r.URL.Query().Get("path"))
	abs, ok := s.wsResolve(rawPath)
	if filepath.IsAbs(rawPath) {
		base := filepath.Clean(s.m.dir)
		candidate := filepath.Clean(rawPath)
		ok = (candidate == base || strings.HasPrefix(candidate, base+string(os.PathSeparator))) && s.wsContainsResolved(candidate)
		if ok {
			abs = candidate
		}
	}
	if !ok {
		writeErr(w, 400, "Invalid path")
		return
	}
	fi, err := os.Stat(abs)
	// Reports use the workspace-relative canonical path
	// findings/screenshots/finding-<node>-step-<n>.png, while the files live
	// under the per-conversation session directory. Resolve that exact suffix
	// in the newest matching session so the links stay portable across reports.
	if (err != nil || fi.IsDir()) && !filepath.IsAbs(rawPath) {
		if fallback, found := s.findSessionPreview(rawPath); found {
			abs = fallback
			fi, err = os.Stat(abs)
		}
	}
	if err != nil || fi.IsDir() {
		writeErr(w, 404, "File does not exist")
		return
	}
	ext := strings.ToLower(filepath.Ext(abs))
	if ext != ".png" && ext != ".jpg" && ext != ".jpeg" && ext != ".webp" && ext != ".gif" {
		writeErr(w, 415, "Only image preview is supported")
		return
	}
	if s.m.pg.GetBool(settingScreenshotTimestamp, false) {
		rawRel := filepath.ToSlash(strings.TrimPrefix(strings.TrimSpace(rawPath), "/"))
		rel := filepath.ToSlash(s.wsRel(abs))
		if strings.HasPrefix(rawRel, "findings/screenshots/") || strings.HasPrefix(rel, "findings/screenshots/") || strings.Contains(rel, "/findings/screenshots/") {
			// The frontend renders this as a small top-right overlay. Use the
			// file mtime so the label reflects capture/save time, not view time.
			// Containers may run with UTC even when the host is configured for
			// China Standard Time, so make the report display zone explicit.
			w.Header().Set("X-Report-Screenshot-Timestamp", reportScreenshotTimestamp(fi.ModTime()))
		}
	}
	w.Header().Set("Content-Disposition", "inline; filename=\""+sanitizeFilename(filepath.Base(abs))+"\"")
	http.ServeFile(w, r, abs)
}

func reportScreenshotTimestamp(t time.Time) string {
	return t.In(time.FixedZone("CST", 8*60*60)).Format("2006-01-02 15:04:05")
}

func (s *Server) findSessionPreview(rawPath string) (string, bool) {
	rel := filepath.Clean(strings.TrimPrefix(strings.TrimSpace(rawPath), "/"))
	const prefix = "findings" + string(os.PathSeparator) + "screenshots" + string(os.PathSeparator)
	if rel == "." || !strings.HasPrefix(rel, prefix) || strings.Contains(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	base := filepath.Join(filepath.Clean(s.m.dir), "sessions")
	matches, err := filepath.Glob(filepath.Join(base, "*", filepath.FromSlash(rel)))
	if err != nil || len(matches) == 0 {
		return "", false
	}
	var newest string
	var newestTime int64
	for _, candidate := range matches {
		if !s.wsContainsResolved(candidate) {
			continue
		}
		info, statErr := os.Stat(candidate)
		if statErr != nil || info.IsDir() {
			continue
		}
		mtime := info.ModTime().UnixNano()
		if newest == "" || mtime > newestTime {
			newest, newestTime = candidate, mtime
		}
	}
	return newest, newest != ""
}

// archiveFindingScreenshots materializes report-referenced screenshots in the
// task workspace. Browser runs use per-session working directories, while
// reports intentionally use the portable findings/screenshots/ path.
func (s *Server) archiveFindingScreenshots(taskID int64, markdown string) error {
	if taskID <= 0 {
		return nil
	}
	for _, match := range screenshotMarkdownLink.FindAllStringSubmatch(markdown, -1) {
		raw := strings.TrimSpace(match[2])
		rel := filepath.Clean(strings.TrimPrefix(raw, "/"))
		const prefix = "findings" + string(os.PathSeparator) + "screenshots" + string(os.PathSeparator)
		if !strings.HasPrefix(rel, prefix) || strings.Contains(rel, ".."+string(os.PathSeparator)) {
			continue
		}
		target := filepath.Join(s.m.dir, "tasks", fmt.Sprint(taskID), rel)
		if info, err := os.Stat(target); err == nil && !info.IsDir() {
			continue
		}
		source, ok := s.resolveSessionScreenshot(rel)
		if !ok {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		in, err := os.Open(source)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err == nil {
			_, err = io.Copy(out, in)
		}
		_ = in.Close()
		_ = out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) resolveSessionScreenshot(rel string) (string, bool) {
	matches, err := filepath.Glob(filepath.Join(filepath.Clean(s.m.dir), "sessions", "*", rel))
	if err != nil || len(matches) == 0 {
		return "", false
	}
	var newest string
	var newestTime int64
	for _, candidate := range matches {
		if !s.wsContainsResolved(candidate) {
			continue
		}
		info, statErr := os.Stat(candidate)
		if statErr != nil || info.IsDir() {
			continue
		}
		if newest == "" || info.ModTime().UnixNano() > newestTime {
			newest, newestTime = candidate, info.ModTime().UnixNano()
		}
	}
	return newest, newest != ""
}

// POST /api/workspace/upload?path=<dir> — multipart form field "file" (one or more).
func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	dirAbs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "Invalid path")
		return
	}
	if fi, err := os.Stat(dirAbs); err != nil || !fi.IsDir() {
		writeErr(w, 400, "Target directory does not exist")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "Failed to parse upload or size limit exceeded: "+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "Missing upload file (form field 'file')")
		return
	}
	saved := 0
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." {
			continue
		}
		destAbs, okd := s.wsResolve(filepath.Join(s.wsRel(dirAbs), name))
		if !okd {
			continue
		}
		if err := saveUpload(hdr, destAbs); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		saved++
	}
	writeJSON(w, 200, map[string]any{"uploaded": saved})
}

func saveUpload(hdr *multipart.FileHeader, dest string) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

// sanitizeFilename strips characters unsafe for a Content-Disposition filename token.
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	return name
}
