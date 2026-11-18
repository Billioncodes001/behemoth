// Package patchmonitor provides autonomous security patch monitoring,
// vulnerability tracking, and automated exploit generation/testing capabilities.
package patchmonitor

import (
	"crypto/tls"
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ---------- Types ----------

// PatchSource represents a monitored vulnerability feed.
type PatchSource struct {
	ID                   int64      `json:"id"`
	Name                 string     `json:"name"`
	URL                  string     `json:"url"`
	SourceType           string     `json:"source_type"`
	CheckInterval        int        `json:"check_interval"`         // seconds
	CheckIntervalMinutes int        `json:"check_interval_minutes"` // minutes (UI convenience)
	Enabled              bool       `json:"enabled"`
	IsActive             bool       `json:"is_active"`
	LastCheck            *time.Time `json:"last_check,omitempty"`
	LastCheckAt          *time.Time `json:"last_check_at"`
	LastHash             string     `json:"last_hash,omitempty"`
	LastStatus           string     `json:"last_status,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

// Vulnerability represents a discovered security vulnerability/patch.
type Vulnerability struct {
	ID               int64     `json:"id"`
	SourceID         *int64    `json:"source_id,omitempty"`
	SourceName       string    `json:"source_name"`
	CVEID            string    `json:"cve_id,omitempty"`
	Title            string    `json:"title"`
	Description      string    `json:"description,omitempty"`
	Severity         string    `json:"severity"`
	CVSSScore        *float64  `json:"cvss_score,omitempty"`
	AffectedSoftware string    `json:"affected_software,omitempty"`
	AffectedVersions string    `json:"affected_versions,omitempty"`
	PatchedVersion   string    `json:"patched_version,omitempty"`
	PatchURL         string    `json:"patch_url,omitempty"`
	DiffSummary      string    `json:"diff_summary,omitempty"`
	Status           string    `json:"status"` // active, patched, exploitable, new
	DiscoveredAt     time.Time `json:"discovered_at"`
}

// Exploit represents a generated exploit for a vulnerability.
type Exploit struct {
	ID          int64     `json:"id"`
	VulnID      int64     `json:"vuln_id"`
	ExploitCode string    `json:"exploit_code"`
	Language    string    `json:"language"`
	Type        string    `json:"type"` // poc, full, dos, rce
	SuccessRate float64   `json:"success_rate"`
	CreatedAt   time.Time `json:"created_at"`
}

// ExploitTarget represents a target for automated exploit testing.
type ExploitTarget struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	TargetType  string    `json:"target_type"` // web, api, host, network
	TargetValue string    `json:"target_value"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Service     string    `json:"service,omitempty"`
	Version     string    `json:"version,omitempty"`
	OSType      string    `json:"os_type,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	Status      string    `json:"status"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// TestResult represents the result of an exploit test against a target.
type TestResult struct {
	ID        int64     `json:"id"`
	ExploitID int64     `json:"exploit_id"`
	TargetID  *int64    `json:"target_id,omitempty"`
	Status    string    `json:"status"` // success, failed, error, timeout
	Output    string    `json:"output,omitempty"`
	TestedAt  time.Time `json:"tested_at"`
}

// Monitor is the main patch monitoring orchestrator.
type Monitor struct {
	db                 *sql.DB
	httpClient         *http.Client
	proxyAddrFn        func() string
	mu                 sync.RWMutex
	running            bool
	autoPayload        bool
	llmProfileID       *int64
	lastConversationID int64
	lastScanAt         *time.Time
	onAgentWatch       func(profileID *int64, newVulns []Vulnerability, sourcesChecked int) int64
	stopCh             chan struct{}
	wg                 sync.WaitGroup
}

// SetProxyProvider configures an optional dynamic proxy URL provider so outbound
// feed requests route through the active Global Proxy / Proxy Pool when enabled.
func (m *Monitor) SetProxyProvider(fn func() string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxyAddrFn = fn
}

func (m *Monitor) client() *http.Client {
	m.mu.RLock()
	fn := m.proxyAddrFn
	base := m.httpClient
	m.mu.RUnlock()
	if fn != nil {
		if raw := strings.TrimSpace(fn()); raw != "" {
			if u, err := url.Parse(raw); err == nil && u.Host != "" {
				return &http.Client{
					Timeout: 30 * time.Second,
					Transport: &http.Transport{
						Proxy:           http.ProxyURL(u),
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					},
				}
			}
		}
	}
	return base
}

// NewMonitor creates a new PatchMonitor instance and ensures database tables & seeds exist.
func NewMonitor(db *sql.DB) *Monitor {
	m := &Monitor{
		db:          db,
		autoPayload: true,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
	if db != nil {
		m.ensureSchemaAndSeeds()
	}
	return m
}

// SetAgentWatchCallback wires the AI agent trigger invoked when a watch cycle runs.
func (m *Monitor) SetAgentWatchCallback(fn func(profileID *int64, newVulns []Vulnerability, sourcesChecked int) int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onAgentWatch = fn
}

// Configure updates the monitor's LLM profile and auto-payload generation settings.
func (m *Monitor) Configure(profileID *int64, autoPayload bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.llmProfileID = profileID
	m.autoPayload = autoPayload
}

// AutoPayloadEnabled reports whether automatic exploit & payload generation is enabled.
func (m *Monitor) AutoPayloadEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.autoPayload
}

// StatusSnapshot returns the current runtime state of the Patch Monitor.
func (m *Monitor) StatusSnapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]interface{}{
		"running":              m.running,
		"auto_payload":         m.autoPayload,
		"llm_profile_id":       m.llmProfileID,
		"last_conversation_id": m.lastConversationID,
		"last_scan_at":         m.lastScanAt,
		"checked_at":           time.Now(),
	}
}


