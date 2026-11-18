package patchmonitor

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

func (m *Monitor) ensureSchemaAndSeeds() {
	ddl := `
CREATE TABLE IF NOT EXISTS patch_sources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    url VARCHAR(2048) NOT NULL,
    source_type VARCHAR(50) DEFAULT 'custom',
    check_interval INT DEFAULT 3600,
    enabled BOOLEAN DEFAULT true,
    last_check TIMESTAMPTZ,
    last_hash VARCHAR(64),
    last_status VARCHAR(50),
    error_message TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS patch_vulnerabilities (
    id SERIAL PRIMARY KEY,
    source_id INTEGER REFERENCES patch_sources(id) ON DELETE SET NULL,
    cve_id VARCHAR(64),
    title TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'medium',
    cvss_score DECIMAL(3,1),
    affected_software VARCHAR(512),
    affected_versions VARCHAR(512),
    patched_version VARCHAR(512),
    patch_url VARCHAR(2048),
    diff_summary TEXT,
    raw_data JSONB,
    status VARCHAR(30) DEFAULT 'active',
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE patch_vulnerabilities ADD COLUMN IF NOT EXISTS affected_versions VARCHAR(512);
ALTER TABLE patch_vulnerabilities ADD COLUMN IF NOT EXISTS patched_version VARCHAR(512);
CREATE TABLE IF NOT EXISTS generated_exploits (
    id SERIAL PRIMARY KEY,
    vuln_id INTEGER REFERENCES patch_vulnerabilities(id) ON DELETE CASCADE,
    cve_id VARCHAR(64),
    exploit_type VARCHAR(50) DEFAULT 'poc',
    code TEXT NOT NULL DEFAULT '',
    exploit_code TEXT NOT NULL DEFAULT '',
    language VARCHAR(50) DEFAULT 'python',
    type VARCHAR(50) DEFAULT 'poc',
    confidence FLOAT DEFAULT 0.5,
    code_hash VARCHAR(64),
    success_rate FLOAT DEFAULT 0,
    status VARCHAR(30) DEFAULT 'draft',
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE generated_exploits ADD COLUMN IF NOT EXISTS cve_id VARCHAR(64);
ALTER TABLE generated_exploits ADD COLUMN IF NOT EXISTS exploit_type VARCHAR(50) DEFAULT 'poc';
ALTER TABLE generated_exploits ADD COLUMN IF NOT EXISTS code TEXT NOT NULL DEFAULT '';
ALTER TABLE generated_exploits ADD COLUMN IF NOT EXISTS confidence FLOAT DEFAULT 0.5;
CREATE TABLE IF NOT EXISTS exploit_targets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    target_type VARCHAR(50) NOT NULL DEFAULT 'web',
    target_value VARCHAR(512) NOT NULL DEFAULT '',
    host VARCHAR(512) NOT NULL DEFAULT '',
    port INT NOT NULL DEFAULT 80,
    service VARCHAR(255),
    version VARCHAR(255),
    os_type VARCHAR(128),
    notes TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'online',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE exploit_targets ADD COLUMN IF NOT EXISTS host VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE exploit_targets ADD COLUMN IF NOT EXISTS port INT NOT NULL DEFAULT 80;
ALTER TABLE exploit_targets ADD COLUMN IF NOT EXISTS service VARCHAR(255);
ALTER TABLE exploit_targets ADD COLUMN IF NOT EXISTS version VARCHAR(255);
ALTER TABLE exploit_targets ADD COLUMN IF NOT EXISTS os_type VARCHAR(128);
ALTER TABLE exploit_targets ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE exploit_targets ADD COLUMN IF NOT EXISTS status VARCHAR(50) NOT NULL DEFAULT 'online';
CREATE TABLE IF NOT EXISTS exploit_test_results (
    id SERIAL PRIMARY KEY,
    exploit_id INTEGER REFERENCES generated_exploits(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES exploit_targets(id) ON DELETE SET NULL,
    target_name VARCHAR(255),
    output TEXT,
    success BOOLEAN,
    error_code VARCHAR(50),
    duration_ms BIGINT DEFAULT 0,
    tested_at TIMESTAMPTZ DEFAULT NOW()
);`
	if _, err := m.db.Exec(ddl); err != nil {
		log.Printf("[patchmonitor] Schema init warning: %v", err)
	}

	_, _ = m.db.Exec(`
INSERT INTO patch_sources (name, url, source_type, check_interval, enabled) VALUES
    ('NVD Recent CVEs', 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20', 'nvd', 3600, true),
    ('GitHub Security Advisories', 'https://api.github.com/advisories?per_page=20', 'github', 1800, true),
    ('Exploit-DB RSS Feed', 'https://www.exploit-db.com/rss.xml', 'exploitdb', 3600, true)
ON CONFLICT (name) DO NOTHING`)

	var count int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM patch_vulnerabilities`).Scan(&count); err == nil && count == 0 {
		var srcID sql.NullInt64
		_ = m.db.QueryRow(`SELECT id FROM patch_sources ORDER BY id LIMIT 1`).Scan(&srcID)
		_, _ = m.db.Exec(`
INSERT INTO patch_vulnerabilities (source_id, cve_id, title, description, severity, cvss_score, affected_versions, patched_version, status) VALUES
    ($1, 'CVE-2024-4577', 'PHP CGI Argument Injection RCE', 'PHP CGI on Windows/XAMPP fails to properly sanitize Best-Fit character mappings, allowing unauthenticated remote code execution via query string arguments.', 'critical', 9.8, 'PHP 8.1.* < 8.1.29, 8.2.* < 8.2.20, 8.3.* < 8.3.8', '8.3.8 / 8.2.20 / 8.1.29', 'exploitable'),
    ($1, 'CVE-2024-6387', 'OpenSSH regreSSHion Unauthenticated RCE', 'Signal handler race condition in OpenSSH server (sshd) on glibc-based Linux systems allows unauthenticated remote code execution as root.', 'high', 8.1, 'OpenSSH 8.5p1 - 9.7p1', '9.8p1', 'active'),
    ($1, 'CVE-2024-3400', 'Palo Alto PAN-OS GlobalProtect Command Injection', 'Unauthenticated command injection in the GlobalProtect gateway telemetry feature of Palo Alto Networks PAN-OS software.', 'critical', 10.0, 'PAN-OS 10.2, 11.0, 11.1', '11.1.2-h3 / 11.0.4-h1', 'exploitable'),
    ($1, 'CVE-2024-27198', 'JetBrains TeamCity Authentication Bypass RCE', 'Path traversal in JetBrains TeamCity web server allows complete authentication bypass and administrative token creation leading to RCE.', 'critical', 9.8, 'TeamCity < 2023.11.4', '2023.11.4', 'patched')`, srcID)
	}
}


func scanSourceRow(rows *sql.Rows) (PatchSource, error) {
	var s PatchSource
	var lastHash, lastStatus sql.NullString
	err := rows.Scan(&s.ID, &s.Name, &s.URL, &s.SourceType, &s.CheckInterval,
		&s.Enabled, &s.LastCheck, &lastHash, &lastStatus, &s.CreatedAt)
	if err != nil {
		return s, err
	}
	s.LastHash = lastHash.String
	s.LastStatus = lastStatus.String
	s.IsActive = s.Enabled
	s.LastCheckAt = s.LastCheck
	if s.CheckInterval > 0 {
		s.CheckIntervalMinutes = s.CheckInterval / 60
		if s.CheckIntervalMinutes == 0 {
			s.CheckIntervalMinutes = 1
		}
	} else {
		s.CheckIntervalMinutes = 60
	}
	return s, nil
}

// GetEnabledSources returns all enabled patch sources.
func (m *Monitor) GetEnabledSources() ([]PatchSource, error) {
	rows, err := m.db.Query(`
		SELECT id, name, url, source_type, check_interval, enabled, last_check, last_hash, last_status, created_at
		FROM patch_sources WHERE enabled = true ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sources := make([]PatchSource, 0)
	for rows.Next() {
		s, err := scanSourceRow(rows)
		if err != nil {
			log.Printf("[patchmonitor] Row scan error: %v", err)
			continue
		}
		sources = append(sources, s)
	}
	return sources, nil
}

// GetAllSources returns all patch sources (including disabled).
func (m *Monitor) GetAllSources() ([]PatchSource, error) {
	rows, err := m.db.Query(`
		SELECT id, name, url, source_type, check_interval, enabled, last_check, last_hash, last_status, created_at
		FROM patch_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sources := make([]PatchSource, 0)
	for rows.Next() {
		s, err := scanSourceRow(rows)
		if err != nil {
			continue
		}
		sources = append(sources, s)
	}
	return sources, nil
}

// storeVulnerability inserts a new vulnerability (ignoring duplicates by CVE ID).
func (m *Monitor) storeVulnerability(sourceID int64, v Vulnerability) error {
	status := v.Status
	if status == "" || status == "new" {
		status = "active"
	}
	_, err := m.db.Exec(`
		INSERT INTO patch_vulnerabilities (source_id, cve_id, title, description, severity, cvss_score, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT DO NOTHING`,
		sourceID, v.CVEID, v.Title, v.Description, v.Severity, v.CVSSScore, status)
	return err
}

// GetVulnerabilities returns vulnerabilities with optional filtering.
func (m *Monitor) GetVulnerabilities(status string, limit int) ([]Vulnerability, error) {
	query := `
		SELECT pv.id, pv.source_id, COALESCE(ps.name, 'Built-in Feed') as source_name,
		       COALESCE(pv.cve_id, ''), pv.title, COALESCE(pv.description, ''),
		       COALESCE(pv.severity, 'medium'), pv.cvss_score,
		       COALESCE(pv.affected_versions, ''), COALESCE(pv.patched_version, ''),
		       COALESCE(pv.patch_url, ''), COALESCE(pv.diff_summary, ''),
		       COALESCE(pv.status, 'active'), pv.discovered_at
		FROM patch_vulnerabilities pv
		LEFT JOIN patch_sources ps ON ps.id = pv.source_id
		WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if status != "" && status != "all" {
		query += fmt.Sprintf(" AND pv.status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY pv.discovered_at DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	vulns := make([]Vulnerability, 0)
	for rows.Next() {
		var v Vulnerability
		if err := rows.Scan(&v.ID, &v.SourceID, &v.SourceName, &v.CVEID, &v.Title, &v.Description,
			&v.Severity, &v.CVSSScore, &v.AffectedVersions, &v.PatchedVersion,
			&v.PatchURL, &v.DiffSummary, &v.Status, &v.DiscoveredAt); err != nil {
			log.Printf("[patchmonitor] Vuln scan error: %v", err)
			continue
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// AddTarget adds a new exploit target.
func (m *Monitor) AddTarget(t ExploitTarget) (int64, error) {
	t.Name = strings.TrimSpace(t.Name)
	t.Host = strings.TrimSpace(t.Host)
	t.TargetValue = strings.TrimSpace(t.TargetValue)
	if t.TargetType == "" {
		t.TargetType = "web"
	}
	if t.Port <= 0 {
		t.Port = 80
	}
	if t.Host == "" && t.TargetValue != "" {
		t.Host = t.TargetValue
	}
	if t.TargetValue == "" && t.Host != "" {
		t.TargetValue = fmt.Sprintf("%s:%d", t.Host, t.Port)
	}
	if t.Status == "" {
		t.Status = "online"
	}
	t.Enabled = true

	var id int64
	err := m.db.QueryRow(`
		INSERT INTO exploit_targets (name, target_type, target_value, host, port, service, version, os_type, notes, status, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
		t.Name, t.TargetType, t.TargetValue, t.Host, t.Port, t.Service, t.Version, t.OSType, t.Notes, t.Status, t.Enabled).Scan(&id)
	return id, err
}

// GetTargets returns all exploit targets.
func (m *Monitor) GetTargets() ([]ExploitTarget, error) {
	rows, err := m.db.Query(`
		SELECT id, name, target_type, target_value, COALESCE(host, ''), COALESCE(port, 80),
		       COALESCE(service, ''), COALESCE(version, ''), COALESCE(os_type, ''),
		       COALESCE(notes, ''), COALESCE(status, 'online'), enabled, created_at
		FROM exploit_targets ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	targets := make([]ExploitTarget, 0)
	for rows.Next() {
		var t ExploitTarget
		if err := rows.Scan(&t.ID, &t.Name, &t.TargetType, &t.TargetValue, &t.Host, &t.Port,
			&t.Service, &t.Version, &t.OSType, &t.Notes, &t.Status, &t.Enabled, &t.CreatedAt); err != nil {
			continue
		}
		if t.Host == "" {
			t.Host = t.TargetValue
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// DeleteTarget deletes an exploit target by ID.
func (m *Monitor) DeleteTarget(id int64) error {
	_, err := m.db.Exec(`DELETE FROM exploit_targets WHERE id = $1`, id)
	return err
}

// updateSourceStatus updates a source's last check status.
func (m *Monitor) updateSourceStatus(sourceID int64, status, msg string) {
	_, err := m.db.Exec(`
		UPDATE patch_sources SET last_status = $1, error_message = $2, last_check = $3, updated_at = NOW()
		WHERE id = $4`, status, msg, time.Now(), sourceID)
	if err != nil {
		log.Printf("[patchmonitor] Update status error: %v", err)
	}
}

// updateSourceHash updates a source's hash after successful check.
func (m *Monitor) updateSourceHash(sourceID int64, hash, status, msg string) {
	_, err := m.db.Exec(`
		UPDATE patch_sources SET last_hash = $1, last_status = $2, error_message = $3, last_check = $4, updated_at = NOW()
		WHERE id = $5`, hash, status, msg, time.Now(), sourceID)
	if err != nil {
		log.Printf("[patchmonitor] Update hash error: %v", err)
	}
}
