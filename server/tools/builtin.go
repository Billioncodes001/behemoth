package tools

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// registerBuiltInTools registers default security tools (HexStrike-inspired).
func (c *Catalog) registerBuiltInTools() {
	tools := []*Tool{
		// === RECONNAISSANCE ===
		{
			ID: "nmap-scan", Name: "Nmap Port Scanner",
			Description: "Network discovery and security auditing",
			Category: "recon", Version: "7.95", Command: "nmap",
			Parameters: []ToolParameter{
				{Name: "target", Type: "string", Required: true, Description: "Target IP or hostname"},
				{Name: "ports", Type: "string", Required: false, Default: "1-1000", Description: "Port range"},
				{Name: "service-detection", Type: "bool", Required: false, Default: true, Flag: "-sV"},
				{Name: "os-detection", Type: "bool", Required: false, Default: false, Flag: "-O"},
				{Name: "script-scan", Type: "bool", Required: false, Default: false, Flag: "-sC"},
				{Name: "aggressive", Type: "bool", Required: false, Default: false, Flag: "-A"},
			},
			ParseOutput: true, OutputType: "xml",
			Tags: []string{"network", "scanning", "ports"}, RiskLevel: "low", Timeout: 15 * time.Minute,
		},
		{
			ID: "subfinder", Name: "Subfinder",
			Description: "Subdomain discovery tool",
			Category: "recon", Version: "2.6", Command: "subfinder",
			Parameters: []ToolParameter{
				{Name: "domain", Type: "domain", Required: true, Description: "Target domain"},
				{Name: "silent", Type: "bool", Required: false, Default: true, Flag: "-silent"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"subdomain", "osint"}, RiskLevel: "low", Timeout: 5 * time.Minute,
		},
		{
			ID: "httpx-probe", Name: "HTTPX",
			Description: "HTTP toolkit for probing",
			Category: "recon", Version: "1.3", Command: "httpx",
			Parameters: []ToolParameter{
				{Name: "list", Type: "string", Required: true, Description: "File with URLs/hosts"},
				{Name: "status-code", Type: "bool", Required: false, Default: true, Flag: "-status-code"},
				{Name: "title", Type: "bool", Required: false, Default: true, Flag: "-title"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"http", "probing"}, RiskLevel: "low", Timeout: 10 * time.Minute,
		},

		// === WEB APPLICATION ===
		{
			ID: "dirb-scan", Name: "Dirb Scanner",
			Description: "Web content discovery",
			Category: "web", Version: "2.23", Command: "dirb",
			Parameters: []ToolParameter{
				{Name: "url", Type: "url", Required: true, Description: "Target URL"},
				{Name: "wordlist", Type: "file", Required: false, Default: "/usr/share/wordlists/dirb/common.txt", Description: "Wordlist path"},
			},
			Tags: []string{"web", "directory", "fuzzing"}, RiskLevel: "medium", Timeout: 15 * time.Minute,
		},
		{
			ID: "gobuster-scan", Name: "Gobuster",
			Description: "Directory/file & DNS busting tool",
			Category: "web", Version: "3.6", Command: "gobuster",
			Parameters: []ToolParameter{
				{Name: "url", Type: "url", Required: true, Description: "Target URL"},
				{Name: "wordlist", Type: "file", Required: false, Default: "/usr/share/wordlists/dirb/common.txt", Description: "Wordlist"},
				{Name: "threads", Type: "int", Required: false, Default: "10", Description: "Concurrency"},
				{Name: "extensions", Type: "string", Required: false, Default: "php,html,js,txt", Description: "Extensions"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"web", "directory", "dns", "fuzzing"}, RiskLevel: "medium", Timeout: 10 * time.Minute,
		},
		{
			ID: "ffuf-fuzz", Name: "FFUF",
			Description: "Fast web fuzzer",
			Category: "web", Version: "2.1", Command: "ffuf",
			Parameters: []ToolParameter{
				{Name: "url", Type: "url", Required: true, Description: "Target URL with FUZZ keyword"},
				{Name: "wordlist", Type: "file", Required: true, Description: "Wordlist file"},
				{Name: "threads", Type: "int", Required: false, Default: "40", Description: "Concurrency"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"web", "fuzzing", "brute-force"}, RiskLevel: "medium", Timeout: 10 * time.Minute,
		},
		{
			ID: "nikto-scan", Name: "Nikto Web Scanner",
			Description: "Web server vulnerability scanner",
			Category: "web", Version: "2.5", Command: "nikto",
			Parameters: []ToolParameter{
				{Name: "host", Type: "url", Required: true, Description: "Target host"},
				{Name: "port", Type: "int", Required: false, Default: "80", Description: "Port number"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"web", "vulnerability", "scanner"}, RiskLevel: "medium", Timeout: 10 * time.Minute,
		},

		// === VULNERABILITY SCANNING ===
		{
			ID: "nuclei-scan", Name: "Nuclei",
			Description: "Vulnerability scanner based on templates",
			Category: "scan", Version: "3.3", Command: "nuclei",
			Parameters: []ToolParameter{
				{Name: "target", Type: "url", Required: true, Description: "Target URL or list file"},
				{Name: "templates", Type: "string", Required: false, Default: "", Description: "Template paths"},
				{Name: "severity", Type: "select", Required: false, Options: []string{"critical", "high", "medium", "low", "info"}, Description: "Filter by severity"},
				{Name: "rate-limit", Type: "int", Required: false, Default: "150", Description: "Requests per second"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"vulnerability", "scanner", "templates", "cve"}, RiskLevel: "medium", Timeout: 30 * time.Minute,
		},

		// === EXPLOITATION ===
		{
			ID: "sqlmap-inject", Name: "SQLMap",
			Description: "Automatic SQL injection detection and exploitation",
			Category: "exploit", Version: "1.8", Command: "sqlmap",
			Parameters: []ToolParameter{
				{Name: "url", Type: "url", Required: true, Description: "Target URL with parameter"},
				{Name: "level", Type: "int", Required: false, Default: "3", Description: "Test level (1-5)"},
				{Name: "risk", Type: "int", Required: false, Default: "2", Description: "Risk level (1-3)"},
				{Name: "batch", Type: "bool", Required: false, Default: true, Description: "Non-interactive mode"},
				{Name: "dbs", Type: "bool", Required: false, Default: false, Flag: "--dbs", Description: "Enumerate DBs"},
				{Name: "dump", Type: "bool", Required: false, Default: false, Flag: "--dump", Description: "Dump table data"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"sqli", "injection", "database"}, RiskLevel: "high", Timeout: 30 * time.Minute,
		},
		{
			ID: "metasploit", Name: "Metasploit Framework",
			Description: "Exploitation framework",
			Category: "exploit", Version: "6.3", Command: "msfconsole",
			Parameters: []ToolParameter{
				{Name: "exploit", Type: "string", Required: true, Description: "Exploit module path"},
				{Name: "payload", Type: "string", Required: false, Description: "Payload module"},
				{Name: "rhosts", Type: "string", Required: true, Description: "Target host"},
				{Name: "rport", Type: "int", Required: false, Description: "Target port"},
			},
			Tags: []string{"exploitation", "framework", "payload"}, RiskLevel: "critical", Timeout: 30 * time.Minute,
		},

		// === POST-EXPLOITATION ===
		{
			ID: "linpeas", Name: "LinPEAS",
			Description: "Linux privilege escalation checker",
			Category: "post", Version: "2.4", Command: "linpeas.sh",
			Parameters: []ToolParameter{},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"privilege-escalation", "linux", "enumeration"}, RiskLevel: "high", Timeout: 15 * time.Minute,
		},
		{
			ID: "winpeas", Name: "WinPEAS",
			Description: "Windows privilege escalation checker",
			Category: "post", Version: "2.3", Command: "winPEASx64.exe",
			Parameters: []ToolParameter{},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"privilege-escalation", "windows", "enumeration"}, RiskLevel: "high", Timeout: 15 * time.Minute,
		},

		// === NETWORK ===
		{
			ID: "responder", Name: "Responder",
			Description: "LLMNR/NTLM poisoning tool",
			Category: "network", Version: "3.1.0.0", Command: "Responder",
			Parameters: []ToolParameter{
				{Name: "interface", Type: "string", Required: true, Description: "Network interface"},
			},
			Tags: []string{"llmnr", "ntlm", "poisoning"}, RiskLevel: "high", Timeout: 0,
		},
		{
			ID: "tcpdump-capture", Name: "TCPDump",
			Description: "Network packet capture",
			Category: "network", Version: "4.99", Command: "tcpdump",
			Parameters: []ToolParameter{
				{Name: "interface", Type: "string", Required: true, Description: "Network interface"},
				{Name: "filter", Type: "string", Required: false, Default: "tcp", Description: "BPF filter"},
				{Name: "count", Type: "int", Required: false, Default: "100", Description: "Packet count"},
			},
			Tags: []string{"sniffing", "packet-capture"}, RiskLevel: "medium", Timeout: 5 * time.Minute,
		},

		// === FORENSICS ===
		{
			ID: "volatility", Name: "Volatility",
			Description: "Memory forensics framework",
			Category: "forensic", Version: "3.0", Command: "vol",
			Parameters: []ToolParameter{
				{Name: "memory-file", Type: "file", Required: true, Description: "Memory dump file"},
				{Name: "profile", Type: "string", Required: false, Description: "OS profile"},
				{Name: "plugin", Type: "string", Required: false, Default: "pslist", Description: "Plugin to run"},
			},
			Tags: []string{"memory", "forensics", "analysis"}, RiskLevel: "low", Timeout: 30 * time.Minute,
		},

		// === CLOUD ===
		{
			ID: "scout-suite", Name: "Scout Suite",
			Description: "Cloud security auditor",
			Category: "cloud", Version: "0.39", Command: "scout",
			Parameters: []ToolParameter{
				{Name: "provider", Type: "select", Required: true, Options: []string{"aws", "azure", "gcp"}, Description: "Cloud provider"},
				{Name: "profile", Type: "string", Required: true, Description: "Profile name"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"cloud", "audit", "aws", "azure", "gcp"}, RiskLevel: "low", Timeout: 15 * time.Minute,
		},
	}
	for _, t := range tools {
		c.tools[t.ID] = t
	}
}

// ============================================================
// OUTPUT PARSERS
// ============================================================

// ParsedResult represents structured parsed output.
type ParsedResult struct {
	Type      string                 `json:"type"`
	Raw       string                 `json:"raw,omitempty"`
	Data      map[string]interface{} `json:"data"`
	Summary   string                 `json:"summary"`
	Timestamp time.Time              `json:"timestamp"`
}

// ParseToolOutput parses raw tool output into structured data.
func ParseToolOutput(toolID string, output string) *ParsedResult {
	result := &ParsedResult{
		Type:      toolID,
		Raw:       output,
		Data:      make(map[string]interface{}),
		Summary:   "",
		Timestamp: time.Now(),
	}

	switch toolID {
	case "nmap-scan":
		parseNmapOutput(result)
	case "nuclei-scan":
		parseNucleiOutput(result)
	case "sqlmap-inject":
		parseSqlmapOutput(result)
	case "subfinder":
		parseSubfinderOutput(result)
	case "gobuster-scan":
		parseGobusterOutput(result)
	default:
		lines := strings.Split(output, "\n")
		result.Data["line_count"] = len(lines)
		result.Summary = fmt.Sprintf("%d lines of output", len(lines))
	}

	return result
}

// parseNmapOutput parses Nmap XML/text output.
func parseNmapOutput(r *ParsedResult) {
	portRegex := regexp.MustCompile(`(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(.*)`)
	matches := portRegex.FindAllStringSubmatch(r.Raw, -1)

	var ports []map[string]string
	for _, m := range matches {
		if len(m) >= 4 && m[3] == "open" {
			ports = append(ports, map[string]string{
				"port":     m[1],
				"protocol": m[2],
				"state":    m[3],
				"service":  strings.TrimSpace(m[4]),
			})
		}
	}
	r.Data["open_ports"] = ports
	r.Data["port_count"] = len(ports)
	r.Summary = fmt.Sprintf("Found %d open ports", len(ports))
}

// parseNucleiOutput parses Nuclei JSON output.
func parseNucleiOutput(r *ParsedResult) {
	var findings []map[string]interface{}
	
	if err := json.Unmarshal([]byte(r.Raw), &findings); err == nil {
		// Successfully parsed JSON
	} else {
		// Extract findings from text output
		vulnRegex := regexp.MustCompile(`\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]`)
		matches := vulnRegex.FindAllStringSubmatch(r.Raw, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				findings = append(findings, map[string]interface{}{
					"severity": m[1],
					"template": "detected",
					"cve":      "",
				})
			}
		}
	}

	r.Data["findings"] = findings
	r.Data["finding_count"] = len(findings)

	severityCount := make(map[string]int)
	for _, f := range findings {
		if s, ok := f["severity"].(string); ok {
			severityCount[s]++
		}
	}
	r.Data["by_severity"] = severityCount
	r.Summary = fmt.Sprintf("Found %d vulnerabilities", len(findings))
}

// parseSqlmapOutput parses SQLMap output.
func parseSqlmapOutput(r *ParsedResult) {
	isVuln := strings.Contains(r.Raw, "is vulnerable") || 
	          strings.Contains(r.Raw, "parameter")
	
	r.Data["vulnerable"] = isVuln
	
	dbRegex := regexp.MustCompile(`current database: '(\S+)'`)
	if m := dbRegex.FindStringSubmatch(r.Raw); m != nil {
		r.Data["database"] = m[1]
	}
	
	tableRegex := regexp.MustCompile(`(\d+) tables?:\s*(.*)`)
	if m := tableRegex.FindStringSubmatch(r.Raw); m != nil {
		r.Data["table_count"] = m[1]
		r.Data["tables"] = strings.Split(m[2], ", ")
	}
	
	if isVuln {
		r.Summary = "SQL Injection vulnerability detected!"
	} else {
		r.Summary = "No SQL Injection vulnerability found"
	}
}

// parseSubfinderOutput parses Subdomain results.
func parseSubfinderOutput(r *ParsedResult) {
	var subdomains []string
	lines := strings.Split(r.Raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && (strings.Contains(line, ".") || isDomain(line)) {
			subdomains = append(subdomains, line)
		}
	}
	r.Data["subdomains"] = subdomains
	r.Data["subdomain_count"] = len(subdomains)
	r.Summary = fmt.Sprintf("Found %d subdomains", len(subdomains))
}

// parseGobusterOutput parses Gobuster directory scan results.
func parseGobusterOutput(r *ParsedResult) {
	var dirs []map[string]string
	statusRegex := regexp.MustCompile(`^(\S+)\s+\[(Status:\s*\d+)\]`)
	
	lines := strings.Split(r.Raw, "\n")
	for _, line := range lines {
		if m := statusRegex.FindStringSubmatch(line); m != nil {
			dirs = append(dirs, map[string]string{
				"path":   m[1],
				"status": m[2],
			})
		}
	}
	r.Data["directories"] = dirs
	r.Data["directory_count"] = len(dirs)
	r.Summary = fmt.Sprintf("Found %d directories/files", len(dirs))
}

var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

func isDomain(s string) bool {
	return domainRegex.MatchString(s) && strings.Contains(s, ".")
}