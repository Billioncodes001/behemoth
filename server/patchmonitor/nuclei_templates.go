package patchmonitor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// nucleiTemplateEntry is one verified exploit ready for template export.
type nucleiTemplateEntry struct {
	ID          int64
	CVEID       string
	Title       string
	Severity    string
	ExploitCode string
	Language    string
	Status      string
}

// SetNucleiTemplatesDir wires the on-disk directory where verified Patch Monitor
// exploits are exported as private nuclei templates. When empty (default) the
// sync is a no-op, so tests and Monitor instances without a data dir stay safe.
func (m *Monitor) SetNucleiTemplatesDir(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nucleiTemplatesDir = dir
}

// SyncNucleiTemplates exports every verified generated exploit from Patch Monitor
// as a nuclei YAML template under the configured directory. This turns the Patch
// Monitor into a self-improving private template repository: the more exploits
// operators verify, the sharper subsequent nuclei scans get. Stale behemoth-*
// template files without a matching verified exploit are pruned.
// Returns the number of template changes (writes + prunes).
func (m *Monitor) SyncNucleiTemplates() (int, error) {
	m.mu.RLock()
	dir := m.nucleiTemplatesDir
	db := m.db
	m.mu.RUnlock()
	if dir == "" || db == nil {
		return 0, nil
	}

	rows, err := db.Query(`
		SELECT e.id, COALESCE(e.cve_id, ''), COALESCE(NULLIF(v.title, ''), COALESCE(e.cve_id, ''), 'behemoth-exploit'),
		       COALESCE(NULLIF(v.severity, ''), 'medium'),
		       COALESCE(NULLIF(e.exploit_code, ''), e.code, ''),
		       COALESCE(e.language, 'python'), COALESCE(e.status, 'draft')
		FROM generated_exploits e
		LEFT JOIN patch_vulnerabilities v ON v.id = e.vuln_id
		WHERE e.status IN ('verified', 'verified_working', 'working')
		ORDER BY e.id ASC`)
	if err != nil {
		return 0, fmt.Errorf("querying verified exploits: %w", err)
	}
	defer rows.Close()

	entries := make([]nucleiTemplateEntry, 0, 16)
	currentFiles := make(map[string]bool, 16)
	for rows.Next() {
		var e nucleiTemplateEntry
		if err := rows.Scan(&e.ID, &e.CVEID, &e.Title, &e.Severity, &e.ExploitCode, &e.Language, &e.Status); err != nil {
			return 0, fmt.Errorf("scanning verified exploit: %w", err)
		}
		name := "behemoth-" + templateSlug(e) + ".yaml"
		if currentFiles[name] {
			continue
		}
		entries = append(entries, e)
		currentFiles[name] = true
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("creating nuclei template dir: %w", err)
	}

	written := 0
	for _, e := range entries {
		name := "behemoth-" + templateSlug(e) + ".yaml"
		path := filepath.Join(dir, name)
		content := nucleiTemplateYAML(e)
		if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
			continue // unchanged
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
			log.Printf("[patchmonitor] nuclei template write failed (%s): %v", name, err)
			continue
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			continue
		}
		written++
	}

	dirEntries, _ := os.ReadDir(dir)
	for _, fi := range dirEntries {
		name := fi.Name()
		if fi.IsDir() || !strings.HasPrefix(name, "behemoth-") || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		if !currentFiles[name] {
			if err := os.Remove(filepath.Join(dir, name)); err == nil {
				written++
			}
		}
	}
	log.Printf("[patchmonitor] nuclei template sync: %d verified exploits -> %d template changes in %s", len(entries), written, dir)
	return written, nil
}

// templateSlug derives a stable, filesystem-safe slug for a verified exploit.
func templateSlug(e nucleiTemplateEntry) string {
	raw := strings.ToLower(strings.TrimSpace(e.CVEID))
	if raw == "" {
		raw = fmt.Sprintf("exploit-%d", e.ID)
	}
	return regexp.MustCompile(`[^a-z0-9-]+`).ReplaceAllString(raw, "-")
}

var (
	httpRequestLineRe = regexp.MustCompile(`(?m)^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+\s*$`)
	urlInCodeRe       = regexp.MustCompile(`https?://[^\s'"<>()\\]+`)
	quotedLiteralRe   = regexp.MustCompile(`["']([A-Za-z0-9_\-/.:]{4,64})["']`)
)

// extractHTTPRequest pulls a raw HTTP request line (method + path) out of
// exploit source code, as commonly embedded in Python PoCs.
func extractHTTPRequest(code string) (method, path string) {
	if m := httpRequestLineRe.FindStringSubmatch(code); m != nil {
		return m[1], m[2]
	}
	if u := urlInCodeRe.FindString(code); u != "" {
		return "GET", pathOrSlash(u)
	}
	return "", ""
}

// pathOrSlash reduces a full URL to its path component (defaulting to "/").
func pathOrSlash(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			return rest[j:]
		}
		return "/"
	}
	if strings.HasPrefix(u, "/") {
		return u
	}
	return "/" + u
}

// extractFingerprintWords pulls distinctive literal strings from exploit code
// that can serve as response-body matchers.
func extractFingerprintWords(code string) []string {
	var words []string
	seen := make(map[string]bool)
	for _, m := range quotedLiteralRe.FindAllStringSubmatch(code, 64) {
		w := m[1]
		lower := strings.ToLower(w)
		// Skip obvious code artifacts; keep plausible fingerprints.
		if seen[w] ||
			strings.HasPrefix(w, "http") ||
			lower == "python" || lower == "requests" ||
			strings.ContainsAny(w, "(){}[]") {
			continue
		}
		seen[w] = true
		words = append(words, w)
		if len(words) >= 5 {
			break
		}
	}
	return words
}

// nucleiTemplateYAML renders a nuclei v3 template for a verified exploit. The
// template embeds nuclei's own template placeholders ({{BaseURL}}), so it is
// built as a raw string — never pass it through Go's template engine.
func nucleiTemplateYAML(e nucleiTemplateEntry) string {
	severity := strings.ToLower(strings.TrimSpace(e.Severity))
	switch severity {
	case "critical", "high", "medium", "low", "info":
		// keep
	case "informational":
		severity = "info"
	default:
		severity = "medium"
	}
	title := strings.TrimSpace(e.Title)
	if title == "" {
		title = "BEHEMOTH verified exploit"
	}
	cve := strings.ToUpper(strings.TrimSpace(e.CVEID))

	var b strings.Builder
	b.WriteString("# Auto-generated by BEHEMOTH Patch Monitor — verified exploit export.\n")
	b.WriteString("# Do not hand-edit: this file is regenerated on every patch-watch sync.\n")
	b.WriteString("id: behemoth-" + templateSlug(e) + "\n")
	b.WriteString("info:\n")
	b.WriteString("  name: " + yamlStr(title) + "\n")
	b.WriteString("  author: behemoth-patch-monitor\n")
	b.WriteString("  severity: " + severity + "\n")
	b.WriteString("  tags: behemoth,patch-monitor\n")
	if cve != "" {
		b.WriteString("  classification:\n    cve-id: " + cve + "\n")
	}
	if line := firstCodeLine(e.ExploitCode); line != "" {
		b.WriteString("  description: " + yamlStr("Verified exploit source (status="+e.Status+"): "+line) + "\n")
	}

	method, path := extractHTTPRequest(e.ExploitCode)
	if path == "" {
		path = "/"
	}
	if method == "" {
		method = "GET"
	}
	b.WriteString("http:\n")
	b.WriteString("  - method: " + method + "\n")
	b.WriteString("    path:\n      - \"{{BaseURL}}" + yamlEscapeKeepBraces(path) + "\"\n")

	words := extractFingerprintWords(e.ExploitCode)
	if len(words) > 0 {
		b.WriteString("    matchers-condition: and\n")
		b.WriteString("    matchers:\n")
		b.WriteString("      - type: status\n        status:\n          - 200\n")
		b.WriteString("      - type: word\n        part: body\n        words:\n")
		for _, w := range words {
			b.WriteString("          - " + yamlStr(w) + "\n")
		}
	} else {
		b.WriteString("    matchers:\n      - type: status\n        status:\n          - 200\n")
	}
	return b.String()
}

// firstCodeLine returns a trimmed one-line summary of exploit source code.
func firstCodeLine(code string) string {
	line := strings.SplitN(strings.ReplaceAll(strings.TrimSpace(code), "\r", ""), "\n", 2)[0]
	line = strings.TrimSpace(line)
	if len(line) > 160 {
		line = line[:160] + "..."
	}
	return line
}

// yamlEscape escapes a string for a double-quoted YAML scalar.
func yamlEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

// yamlEscapeKeepBraces is yamlEscape but preserves "{{" nuclei placeholders.
func yamlEscapeKeepBraces(s string) string {
	if !strings.Contains(s, "{{") {
		return yamlEscape(s)
	}
	return s
}

func yamlStr(s string) string {
	return "\"" + yamlEscape(strings.TrimSpace(s)) + "\""
}
