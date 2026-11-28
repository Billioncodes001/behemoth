package server

import (
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	reValidWorkspaceTLD = regexp.MustCompile(`^[a-z]{2,24}$`)
	reNumericUnitToken  = regexp.MustCompile(`^\d+(?:\.\d+)?[a-z]{1,3}$`)
)

// nonTargetWorkspaceDomains lists platform/tool/mirror hosts that should never
// become top-level penetration-test target folders under workspace/domains/.
var nonTargetWorkspaceDomains = map[string]bool{
	"localhost":                 true,
	"github.com":                true,
	"githubusercontent.com":     true,
	"jsdelivr.net":              true,
	"internaldirective.org":     true,
	"iproyal.com":               true,
	"webshare.io":               true,
	"2captcha.com":              true,
	"tavily.com":                true,
	"brave.com":                 true,
	"firecrawl.dev":             true,
	"archive.org":               true,
	"crt.sh":                    true,
	"rdap.org":                  true,
	"cloudflare.com":            true,
	"google.com":                true,
	"googleapis.com":            true,
	"w3.org":                    true,
	"schema.org":                true,
	"example.com":               true,
	"example.org":               true,
	"example.net":               true,
}

// isValidTargetWorkspaceDomain validates that raw is a genuine target domain
// (rejecting numeric tokens like "1.27m", file extensions, bounty platforms,
// and BEHEMOTH's own management/tool hosts).
func isValidTargetWorkspaceDomain(raw string) bool {
	h := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
	if h == "" || !strings.Contains(h, ".") || strings.HasPrefix(h, ".") {
		return false
	}
	if reNumericUnitToken.MatchString(h) {
		return false
	}
	parts := strings.Split(h, ".")
	tld := parts[len(parts)-1]
	if !reValidWorkspaceTLD.MatchString(tld) || nonDomainExts[tld] {
		return false
	}
	// First label must contain at least one letter (rejects "1.27m", "3.05bpw", etc.)
	hasAlpha := false
	for _, r := range parts[0] {
		if r >= 'a' && r <= 'z' {
			hasAlpha = true
			break
		}
	}
	if !hasAlpha {
		return false
	}
	base := baseDomainOf(h)
	if nonTargetWorkspaceDomains[h] || nonTargetWorkspaceDomains[base] || isKnownBountyPlatformHost(h) {
		return false
	}
	return true
}

type workspaceSearchResult struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Path        string `json:"path"`
	Parent      string `json:"parent"`
	Dir         bool   `json:"dir"`
	Size        int64  `json:"size"`
	Mtime       int64  `json:"mtime"`
	Kind        string `json:"kind"`
}

// GET /api/workspace/search?q=<query>&path=<optional>&limit=<optional>
// Recursively searches files and folders across the workspace (domains, tasks,
// sessions, reports) without breaking any active task/worker paths.
func (s *Server) wsSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if q == "" {
		writeJSON(w, 200, map[string]any{"query": "", "items": []workspaceSearchResult{}, "truncated": false})
		return
	}
	relRoot := strings.TrimSpace(r.URL.Query().Get("path"))
	limit := 80
	if rawLim := strings.TrimSpace(r.URL.Query().Get("limit")); rawLim != "" {
		if n, err := strconv.Atoi(rawLim); err == nil && n > 0 && n <= 300 {
			limit = n
		}
	}
	startAbs, ok := s.wsResolve(relRoot)
	if !ok {
		writeErr(w, 400, "invalid workspace path")
		return
	}
	baseRoot := filepath.Clean(s.m.dir)
	skipDirs := map[string]bool{
		"_blobs":       true,
		"_index":       true,
		"_ca":          true,
		"builtin-mcp":  true,
		"colab-g4":     true,
		"node_modules": true,
		".git":         true,
		"wordlists":    true,
	}

	var results []workspaceSearchResult
	truncated := false
	seenPath := map[string]bool{}

	_ = filepath.WalkDir(startAbs, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if p == startAbs {
			return nil
		}
		if d.IsDir() && skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		// Never traverse symlinks during recursive search to avoid loops or duplicate hits.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, rerr := filepath.Rel(baseRoot, p)
		if rerr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if seenPath[relSlash] {
			return nil
		}
		lowName := strings.ToLower(d.Name())
		lowPath := strings.ToLower(relSlash)
		if !strings.Contains(lowName, q) && !strings.Contains(lowPath, q) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		parent := filepath.ToSlash(filepath.Dir(rel))
		if parent == "." {
			parent = ""
		}
		kind := "file"
		if d.IsDir() {
			kind = "dir"
		} else {
			switch strings.ToLower(filepath.Ext(d.Name())) {
			case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg":
				kind = "image"
			case ".md", ".txt", ".json", ".yaml", ".yml", ".xml", ".html", ".htm", ".csv", ".log", ".py", ".sh", ".js", ".ts", ".go", ".sql", ".env", ".conf", ".ini":
				kind = "text"
			}
		}
		seenPath[relSlash] = true
		results = append(results, workspaceSearchResult{
			Name:   d.Name(),
			Path:   relSlash,
			Parent: parent,
			Dir:    d.IsDir(),
			Size:   info.Size(),
			Mtime:  info.ModTime().UnixMilli(),
			Kind:   kind,
		})
		if len(results) >= limit {
			truncated = true
			return fs.SkipAll
		}
		return nil
	})

	sort.Slice(results, func(i, j int) bool {
		// Prioritize domains/ hits, then exact filename matches, then newest mtime.
		iDom := strings.HasPrefix(results[i].Path, "domains/")
		jDom := strings.HasPrefix(results[j].Path, "domains/")
		if iDom != jDom {
			return iDom
		}
		if results[i].Dir != results[j].Dir {
			return !results[i].Dir
		}
		return results[i].Mtime > results[j].Mtime
	})

	writeJSON(w, 200, map[string]any{
		"query":     q,
		"items":     results,
		"truncated": truncated,
	})
}

type WorkspaceOrganizeReport struct {
	OK                 bool     `json:"ok"`
	DomainsConsolidated int     `json:"domains_consolidated"`
	TaskFilesSynced    int      `json:"task_files_synced"`
	TasksLinked        int      `json:"tasks_linked"`
	SessionsLinked     int      `json:"sessions_linked"`
	BogusRemoved       int      `json:"bogus_removed"`
	RootDomains        []string `json:"root_domains"`
}

// POST /api/workspace/organize — zero-conflict workspace organizer:
// consolidates subdomain folders under their root domain (`domains/<root>/`),
// syncs real files written inside `tasks/<id>/domains/...` into `domains/<root>/`,
// symlinks non-empty Task and Conversation folders under `domains/<root>/tasks/`
// and `domains/<root>/conversations/`, and removes empty bogus folders (`1.27m`,
// `bugcrowd.com`, etc.) — WITHOUT ever moving or breaking `tasks/<id>/` or
// `sessions/conv-<id>/` so active/resumable agents remain 100% unaffected.
func (s *Server) wsOrganize(w http.ResponseWriter, r *http.Request) {
	rep := s.organizeWorkspaceZeroConflict()
	writeJSON(w, 200, rep)
}

func dirHasRealFiles(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() {
			// Ignore empty auto-generated CREDENTIALS.md stub (header-only <= 260 bytes)
			if strings.EqualFold(d.Name(), "CREDENTIALS.md") {
				if info, ierr := d.Info(); ierr == nil && info.Size() <= 260 {
					return nil
				}
			}
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func copyFileIfNewer(src, dst string) (bool, error) {
	srcInfo, err := os.Stat(src)
	if err != nil || srcInfo.IsDir() {
		return false, err
	}
	if dstInfo, err := os.Stat(dst); err == nil {
		if dstInfo.Size() == srcInfo.Size() && !srcInfo.ModTime().After(dstInfo.ModTime()) {
			return false, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	// Prefer a hardlink (zero disk overhead, instant), falling back to copy across mounts.
	_ = os.Remove(dst)
	if err := os.Link(src, dst); err == nil {
		return true, nil
	}
	in, err := os.Open(src)
	if err != nil {
		return false, err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return false, err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return false, copyErr
	}
	return true, closeErr
}

// syncTreeInto copies/hardlinks every non-symlink file from srcDir into dstDir
// (preserving directory structure) without deleting or moving srcDir.
func syncTreeInto(srcDir, dstDir string) int {
	synced := 0
	_ = filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == srcDir {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(srcDir, p)
		if rerr != nil {
			return nil
		}
		if ok, cerr := copyFileIfNewer(p, filepath.Join(dstDir, rel)); cerr == nil && ok {
			synced++
		}
		return nil
	})
	return synced
}

// syncTaskDomainsToWorkspace mirrors any files a Task wrote under
// `tasks/<id>/domains/<host>/...` into `<workDir>/domains/<rootDomain>/...`
// without modifying `tasks/<id>/`.
func (s *Server) syncTaskDomainsToWorkspace(taskID string, fallbackDomain string) int {
	if s == nil || s.m == nil || strings.TrimSpace(s.m.dir) == "" || taskID == "" {
		return 0
	}
	taskDomRoot := filepath.Join(s.m.dir, "tasks", taskID, "domains")
	entries, err := os.ReadDir(taskDomRoot)
	if err != nil {
		return 0
	}
	synced := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		domName := strings.ToLower(strings.TrimSpace(e.Name()))
		rootDom := ""
		if isValidTargetWorkspaceDomain(domName) {
			rootDom = baseDomainOf(domName)
		} else if isValidTargetWorkspaceDomain(fallbackDomain) {
			rootDom = baseDomainOf(fallbackDomain)
		}
		if rootDom == "" {
			continue
		}
		dst := filepath.Join(s.m.dir, "domains", rootDom)
		synced += syncTreeInto(filepath.Join(taskDomRoot, e.Name()), dst)
	}
	return synced
}

func (s *Server) organizeWorkspaceZeroConflict() WorkspaceOrganizeReport {
	rep := WorkspaceOrganizeReport{OK: true}
	if s == nil || s.m == nil || strings.TrimSpace(s.m.dir) == "" {
		return rep
	}
	domainsRoot := filepath.Join(s.m.dir, "domains")
	_ = os.MkdirAll(domainsRoot, 0o755)

	// 1. Consolidate subdomain folders & prune empty bogus folders inside `domains/`.
	if entries, err := os.ReadDir(domainsRoot); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(e.Name()))
			full := filepath.Join(domainsRoot, e.Name())
			if !isValidTargetWorkspaceDomain(name) {
				if !dirHasRealFiles(full) {
					if os.RemoveAll(full) == nil {
						rep.BogusRemoved++
					}
				}
				continue
			}
			rootDom := baseDomainOf(name)
			if rootDom != "" && rootDom != name {
				dst := filepath.Join(domainsRoot, rootDom)
				_ = os.MkdirAll(dst, 0o755)
				rep.TaskFilesSynced += syncTreeInto(full, dst)
				if os.RemoveAll(full) == nil {
					rep.DomainsConsolidated++
				}
				continue
			}
			// Prune empty stub subdirectories (`evidence`, `portal-simulation`) when they contain 0 files.
			for _, stub := range []string{"evidence", "portal-simulation"} {
				subPath := filepath.Join(full, stub)
				if subEnts, serr := os.ReadDir(subPath); serr == nil && len(subEnts) == 0 {
					_ = os.Remove(subPath)
				}
			}
		}
	}

	// 2. Sync all Task files & link non-empty Task folders under `domains/<root>/tasks/task-<id>`.
	if s.m != nil {
		for _, t := range s.m.List() {
			rawDom := extractPrimaryTargetDomain(t.Name + " " + t.Description + " " + t.Goal)
			rootDom := ""
			if isValidTargetWorkspaceDomain(rawDom) {
				rootDom = baseDomainOf(rawDom)
			}
			rep.TaskFilesSynced += s.syncTaskDomainsToWorkspace(t.ID, rootDom)
			if rootDom == "" {
				continue
			}
			taskAbs := filepath.Join(s.m.dir, "tasks", t.ID)
			if st, err := os.Stat(taskAbs); err != nil || !st.IsDir() || !dirHasRealFiles(taskAbs) {
				continue
			}
			tasksLinkDir := filepath.Join(domainsRoot, rootDom, "tasks")
			_ = os.MkdirAll(tasksLinkDir, 0o755)
			linkPath := filepath.Join(tasksLinkDir, "task-"+t.ID)
			if _, err := os.Lstat(linkPath); os.IsNotExist(err) {
				if os.Symlink(taskAbs, linkPath) == nil {
					rep.TasksLinked++
				}
			}
		}
	}

	// 3. Link non-empty Chat session folders under `domains/<root>/conversations/conv-<id>`.
	sessionsRoot := filepath.Join(s.m.dir, "sessions")
	if entries, err := os.ReadDir(sessionsRoot); err == nil {
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "conv-") {
				continue
			}
			sessAbs := filepath.Join(sessionsRoot, e.Name())
			if !dirHasRealFiles(sessAbs) {
				continue
			}
			dom := ""
			if idNum, perr := strconv.ParseInt(strings.TrimPrefix(e.Name(), "conv-"), 10, 64); perr == nil && idNum > 0 && s.m.pg != nil {
				if conv, cerr := s.m.pg.GetConversation(idNum); cerr == nil && conv != nil {
					dom = extractPrimaryTargetDomain(conv.Title)
				}
			}
			if dom == "" {
				dom = s.sessionDirDomain(sessAbs)
			}
			if !isValidTargetWorkspaceDomain(dom) {
				continue
			}
			rootDom := baseDomainOf(dom)
			convsLinkDir := filepath.Join(domainsRoot, rootDom, "conversations")
			_ = os.MkdirAll(convsLinkDir, 0o755)
			linkPath := filepath.Join(convsLinkDir, e.Name())
			if _, err := os.Lstat(linkPath); os.IsNotExist(err) {
				if os.Symlink(sessAbs, linkPath) == nil {
					rep.SessionsLinked++
				}
			}
		}
	}

	// Collect final clean root domain list.
	if entries, err := os.ReadDir(domainsRoot); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				rep.RootDomains = append(rep.RootDomains, e.Name())
			}
		}
		sort.Strings(rep.RootDomains)
	}
	return rep
}

// runWorkspaceAutoOrganizeOnStartup runs the zero-conflict workspace organizer
// once on boot so existing live servers immediately consolidate subdomains,
// sync task-written domain files, and clean up bogus folders like `1.27m`.
func (s *Server) runWorkspaceAutoOrganizeOnStartup() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	const flag = "workspace_auto_organize_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	go func() {
		time.Sleep(4 * time.Second)
		rep := s.organizeWorkspaceZeroConflict()
		log.Printf("[workspace] Startup zero-conflict organize complete: consolidated=%d synced_files=%d tasks_linked=%d sessions_linked=%d bogus_removed=%d",
			rep.DomainsConsolidated, rep.TaskFilesSynced, rep.TasksLinked, rep.SessionsLinked, rep.BogusRemoved)
		_ = s.m.pg.SetSetting(flag, "true")
	}()
}
