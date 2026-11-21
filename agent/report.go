// Package agent implements report generation for pentest operations.
// Inspired by NukeRat's reporting system (activity, hosts, IOC reports).
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---------- Types ----------

// ReportType represents the type of report.
type ReportType string

const (
	ReportActivity ReportType = "activity"
	ReportHosts    ReportType = "hosts"
	ReportIOC      ReportType = "ioc"
	ReportFull     ReportType = "full"
)

// ReportFormat represents the output format.
type ReportFormat string

const (
	FormatHTML ReportFormat = "html"
	FormatJSON ReportFormat = "json"
	FormatText ReportFormat = "text"
	FormatPDF  ReportFormat = "pdf" // Placeholder
)

// Report represents a generated report.
type Report struct {
	ID          int64        `json:"id"`
	Type        ReportType   `json:"type"`
	Title       string       `json:"title"`
	GeneratedAt time.Time    `json:"generated_at"`
	TaskID      *int64       `json:"task_id,omitempty"`
	Format      ReportFormat `json:"format"`
	Content     []byte       `json:"content"`
	Size        int64        `json:"size"`
}

// ActivityEntry represents a single activity log entry.
type ActivityEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // command, finding, credential, ioc, etc.
	Message   string    `json:"message"`
	Worker    string    `json:"worker,omitempty"`
	Details   string    `json:"details,omitempty"`
}

// HostSummary contains a summary of a target host.
type HostSummary struct {
	Hostname    string    `json:"hostname"`
	IP          string    `json:"ip"`
	OS          string    `json:"os,omitempty"`
	Status      string    `json:"status"`
	NumSessions int       `json:"num_sessions"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	IOCs        []string  `json:"iocs,omitempty"`
	Credentials []string  `json:"credentials,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
}

// IOCSummary contains a summary of an IOC.
type IOCSummary struct {
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Severity  string    `json:"severity"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	Sources   []string  `json:"sources,omitempty"`
}

// FullReportData contains all data for a full report.
type FullReportData struct {
	Metadata    ReportMetadata  `json:"metadata"`
	Activities  []ActivityEntry `json:"activities"`
	Hosts       []HostSummary   `json:"hosts"`
	IOCs        []IOCSummary    `json:"iocs"`
	Credentials []CredSummary   `json:"credentials"`
	Stats       ReportStats     `json:"stats"`
}

// CredSummary contains a summary of a credential.
type CredSummary struct {
	Type     string `json:"type"`
	Username string `json:"username,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Host     string `json:"host,omitempty"`
	Service  string `json:"service,omitempty"`
}

// ReportMetadata contains metadata about the report.
type ReportMetadata struct {
	Title       string    `json:"title"`
	GeneratedAt time.Time `json:"generated_at"`
	TaskID      *int64    `json:"task_id,omitempty"`
	Duration    string    `json:"duration,omitempty"`
	Operator    string    `json:"operator,omitempty"`
}

// ReportStats contains statistics for the report.
type ReportStats struct {
	TotalActivities  int `json:"total_activities"`
	TotalHosts       int `json:"total_hosts"`
	TotalIOCs        int `json:"total_iocs"`
	TotalCredentials int `json:"total_credentials"`
	OnlineSessions   int `json:"online_sessions"`
	HighSeverityIOCs int `json:"high_severity_iocs"`
}

// ---------- Generator ----------

// Generator creates reports from collected data.
type Generator struct {
	config GeneratorConfig
}

// GeneratorConfig holds generator configuration.
type GeneratorConfig struct {
	Title      string `json:"title"`
	Operator   string `json:"operator,omitempty"`
	IncludeRaw bool   `json:"include_raw_data"`
}

// NewGenerator creates a new report generator.
func NewGenerator(config GeneratorConfig) *Generator {
	if config.Title == "" {
		config.Title = "ARTEX Pentest Report"
	}
	return &Generator{config: config}
}

// Generate generates a report in the specified format.
func (g *Generator) Generate(data FullReportData, format ReportFormat) (*Report, error) {
	switch format {
	case FormatHTML:
		return g.generateHTML(data)
	case FormatJSON:
		return g.generateJSON(data)
	case FormatText:
		return g.generateText(data)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// generateJSON generates a JSON report.
func (g *Generator) generateJSON(data FullReportData) (*Report, error) {
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, err
	}
	return &Report{
		Type:        ReportFull,
		Title:       data.Metadata.Title,
		GeneratedAt: time.Now(),
		TaskID:      data.Metadata.TaskID,
		Format:      FormatJSON,
		Content:     content,
		Size:        int64(len(content)),
	}, nil
}

// generateText generates a plain text report.
func (g *Generator) generateText(data FullReportData) (*Report, error) {
	var buf bytes.Buffer

	buf.WriteString("=" + strings.Repeat("=", 69) + "\n")
	buf.WriteString(fmt.Sprintf("  %s\n", data.Metadata.Title))
	buf.WriteString(fmt.Sprintf("  Generated: %s\n", data.Metadata.GeneratedAt.Format("2006-01-02 15:04:05")))
	if data.Metadata.TaskID != nil {
		buf.WriteString(fmt.Sprintf("  Task ID: %d\n", *data.Metadata.TaskID))
	}
	buf.WriteString("=" + strings.Repeat("=", 69) + "\n\n")

	// Stats
	buf.WriteString("EXECUTIVE SUMMARY\n")
	buf.WriteString("-" + strings.Repeat("-", 40) + "\n")
	buf.WriteString(fmt.Sprintf("  Total Activities:    %d\n", data.Stats.TotalActivities))
	buf.WriteString(fmt.Sprintf("  Target Hosts:        %d\n", data.Stats.TotalHosts))
	buf.WriteString(fmt.Sprintf("  IOCs Collected:      %d\n", data.Stats.TotalIOCs))
	buf.WriteString(fmt.Sprintf("  Credentials Found:   %d\n", data.Stats.TotalCredentials))
	buf.WriteString(fmt.Sprintf("  High Severity IOCs:  %d\n", data.Stats.HighSeverityIOCs))
	buf.WriteString("\n")

	// Hosts
	if len(data.Hosts) > 0 {
		buf.WriteString("TARGET HOSTS\n")
		buf.WriteString("-" + strings.Repeat("-", 40) + "\n")
		for _, h := range data.Hosts {
			buf.WriteString(fmt.Sprintf("  [%s] %s (%s)\n", h.Status, h.Hostname, h.IP))
			if h.OS != "" {
				buf.WriteString(fmt.Sprintf("       OS: %s\n", h.OS))
			}
			buf.WriteString(fmt.Sprintf("       Sessions: %d | First Seen: %s\n", h.NumSessions, h.FirstSeen.Format("2006-01-02 15:04")))
		}
		buf.WriteString("\n")
	}

	// IOCs
	if len(data.IOCs) > 0 {
		buf.WriteString("INDICATORS OF COMPROMISE\n")
		buf.WriteString("-" + strings.Repeat("-", 40) + "\n")
		for _, i := range data.IOCs {
			buf.WriteString(fmt.Sprintf("  [%s] %s (seen %dx)\n", strings.ToUpper(i.Severity), i.Value, i.Count))
		}
		buf.WriteString("\n")
	}

	// Credentials
	if len(data.Credentials) > 0 {
		buf.WriteString("CREDENTIALS\n")
		buf.WriteString("-" + strings.Repeat("-", 40) + "\n")
		for _, c := range data.Credentials {
			buf.WriteString(fmt.Sprintf("  [%s] %s@%s (%s)\n", c.Type, c.Username, c.Host, c.Service))
		}
		buf.WriteString("\n")
	}

	content := buf.Bytes()
	return &Report{
		Type:        ReportFull,
		Title:       data.Metadata.Title,
		GeneratedAt: time.Now(),
		TaskID:      data.Metadata.TaskID,
		Format:      FormatText,
		Content:     content,
		Size:        int64(len(content)),
	}, nil
}

// generateHTML generates an HTML report.
func (g *Generator) generateHTML(data FullReportData) (*Report, error) {
	var buf bytes.Buffer

	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>` + data.Metadata.Title + `</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
.header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }
.header h1 { margin: 0; font-size: 24px; }
.header .meta { opacity: 0.8; font-size: 14px; margin-top: 10px; }
.card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.card h2 { margin-top: 0; color: #1a1a2e; border-bottom: 2px solid #e94560; padding-bottom: 10px; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 15px; }
.stat-box { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }
.stat-value { font-size: 28px; font-weight: bold; color: #e94560; }
.stat-label { font-size: 12px; color: #666; text-transform: uppercase; }
table { width: 100%; border-collapse: collapse; margin-top: 15px; }
th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
th { background: #f8f9fa; font-weight: 600; }
.severity-high { color: #dc3545; font-weight: bold; }
.severity-medium { color: #ffc107; }
.severity-low { color: #28a745; }
.status-online { color: #28a745; }
.status-offline { color: #6c757d; }
</style>
</head>
<body>
<div class="header">
<h1>` + data.Metadata.Title + `</h1>
<div class="meta">Generated: ` + data.Metadata.GeneratedAt.Format("2006-01-02 15:04:05") + `</div>
</div>

<div class="card">
<h2>Executive Summary</h2>
<div class="stats-grid">
<div class="stat-box"><div class="stat-value">` + fmt.Sprintf("%d", data.Stats.TotalActivities) + `</div><div class="stat-label">Activities</div></div>
<div class="stat-box"><div class="stat-value">` + fmt.Sprintf("%d", data.Stats.TotalHosts) + `</div><div class="stat-label">Hosts</div></div>
<div class="stat-box"><div class="stat-value">` + fmt.Sprintf("%d", data.Stats.TotalIOCs) + `</div><div class="stat-label">IOCs</div></div>
<div class="stat-box"><div class="stat-value">` + fmt.Sprintf("%d", data.Stats.TotalCredentials) + `</div><div class="stat-label">Credentials</div></div>
<div class="stat-box"><div class="stat-value">` + fmt.Sprintf("%d", data.Stats.HighSeverityIOCs) + `</div><div class="stat-label">High Severity</div></div>
</div>
</div>`)

	// Hosts table
	if len(data.Hosts) > 0 {
		buf.WriteString(`
<div class="card">
<h2>Target Hosts</h2>
<table>
<tr><th>Status</th><th>Hostname</th><th>IP</th><th>OS</th><th>Sessions</th><th>First Seen</th></tr>`)
		for _, h := range data.Hosts {
			statusClass := "status-" + h.Status
			buf.WriteString(fmt.Sprintf(`<tr><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>`,
				statusClass, h.Status, h.Hostname, h.IP, h.OS, h.NumSessions, h.FirstSeen.Format("2006-01-02 15:04")))
		}
		buf.WriteString(`</table></div>`)
	}

	// IOCs table
	if len(data.IOCs) > 0 {
		buf.WriteString(`
<div class="card">
<h2>Indicators of Compromise</h2>
<table>
<tr><th>Severity</th><th>Type</th><th>Value</th><th>Count</th><th>First Seen</th></tr>`)
		for _, i := range data.IOCs {
			sevClass := "severity-" + i.Severity
			buf.WriteString(fmt.Sprintf(`<tr><td class="%s">%s</td><td>%s</td><td><code>%s</code></td><td>%d</td><td>%s</td></tr>`,
				sevClass, strings.ToUpper(i.Severity), i.Type, i.Value, i.Count, i.FirstSeen.Format("2006-01-02 15:04")))
		}
		buf.WriteString(`</table></div>`)
	}

	// Credentials table (sanitized)
	if len(data.Credentials) > 0 {
		buf.WriteString(`
<div class="card">
<h2>Credentials</h2>
<table>
<tr><th>Type</th><th>Username</th><th>Domain</th><th>Host</th><th>Service</th></tr>`)
		for _, c := range data.Credentials {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				c.Type, c.Username, c.Domain, c.Host, c.Service))
		}
		buf.WriteString(`</table></div>`)
	}

	buf.WriteString(`
</body>
</html>`)

	content := buf.Bytes()
	return &Report{
		Type:        ReportFull,
		Title:       data.Metadata.Title,
		GeneratedAt: time.Now(),
		TaskID:      data.Metadata.TaskID,
		Format:      FormatHTML,
		Content:     content,
		Size:        int64(len(content)),
	}, nil
}
