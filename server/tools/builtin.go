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
			Category:    "recon", Version: "7.95", Command: "nmap",
			Parameters: []ToolParameter{
				{Name: "target", Type: "string", Required: true, Description: "Target IP or hostname"},
				{Name: "ports", Type: "string", Required: false, Default: "1-1000", Flag: "-p", Description: "Port range"},
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
			Category:    "recon", Version: "2.6", Command: "subfinder",
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
			Category:    "recon", Version: "1.3", Command: "httpx",
			Parameters: []ToolParameter{
				{Name: "list", Type: "string", Required: true, Flag: "-l", Description: "File with URLs/hosts"},
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
			Category:    "web", Version: "2.23", Command: "dirb",
			Parameters: []ToolParameter{
				{Name: "url", Type: "url", Required: true, Description: "Target URL"},
				{Name: "wordlist", Type: "file", Required: false, Default: "/usr/share/wordlists/dirb/common.txt", Description: "Wordlist path"},
			},
			Tags: []string{"web", "directory", "fuzzing"}, RiskLevel: "medium", Timeout: 15 * time.Minute,
		},
		{
			ID: "gobuster-scan", Name: "Gobuster",
			Description: "Directory/file & DNS busting tool",
			Category:    "web", Version: "3.6", Command: "gobuster",
			FixedArgs: []string{"dir"},
			Parameters: []ToolParameter{
				{Name: "url", Type: "url", Required: true, Flag: "-u", Description: "Target URL"},
				{Name: "wordlist", Type: "file", Required: false, Default: "/usr/share/wordlists/dirb/common.txt", Flag: "-w", Description: "Wordlist"},
				{Name: "threads", Type: "int", Required: false, Default: "10", Flag: "-t", Description: "Concurrency"},
				{Name: "extensions", Type: "string", Required: false, Default: "php,html,js,txt", Flag: "-x", Description: "Extensions"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"web", "directory", "dns", "fuzzing"}, RiskLevel: "medium", Timeout: 10 * time.Minute,
		},
		{
			ID: "ffuf-fuzz", Name: "FFUF",
			Description: "Fast web fuzzer",
			Category:    "web", Version: "2.1", Command: "ffuf",
			Parameters: []ToolParameter{
				{Name: "url", Type: "url", Required: true, Flag: "-u", Description: "Target URL with FUZZ keyword"},
				{Name: "wordlist", Type: "file", Required: true, Flag: "-w", Description: "Wordlist file"},
				{Name: "threads", Type: "int", Required: false, Default: "40", Flag: "-t", Description: "Concurrency"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"web", "fuzzing", "brute-force"}, RiskLevel: "medium", Timeout: 10 * time.Minute,
		},
		{
			ID: "nikto-scan", Name: "Nikto Web Scanner",
			Description: "Web server vulnerability scanner",
			Category:    "web", Version: "2.5", Command: "nikto",
			Parameters: []ToolParameter{
				{Name: "host", Type: "url", Required: true, Flag: "-h", Description: "Target host"},
				{Name: "port", Type: "int", Required: false, Default: "80", Flag: "-p", Description: "Port number"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"web", "vulnerability", "scanner"}, RiskLevel: "medium", Timeout: 10 * time.Minute,
		},

		// === VULNERABILITY SCANNING ===
		{
			ID: "nuclei-scan", Name: "Nuclei",
			Description: "Vulnerability scanner based on templates",
			Category:    "scan", Version: "3.3", Command: "nuclei",
			Parameters: []ToolParameter{
				{Name: "target", Type: "url", Required: true, Description: "Target URL or list file"},
				{Name: "templates", Type: "string", Required: false, Default: "", Flag: "-t", Description: "Template paths (ARTEX auto-injects verified Patch Monitor templates from <data>/nuclei-templates/artex when empty)"},
				{Name: "severity", Type: "select", Required: false, Options: []string{"critical", "high", "medium", "low", "info"}, Flag: "-severity", Description: "Filter by severity"},
				{Name: "rate-limit", Type: "int", Required: false, Default: "150", Flag: "-rl", Description: "Requests per second"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"vulnerability", "scanner", "templates", "cve"}, RiskLevel: "medium", Timeout: 30 * time.Minute,
		},

		// === EXPLOITATION ===
		{
			ID: "sqlmap-inject", Name: "SQLMap",
			Description: "Automatic SQL injection detection and exploitation",
			Category:    "exploit", Version: "1.8", Command: "sqlmap",
			Parameters: []ToolParameter{
				{Name: "url", Type: "url", Required: true, Flag: "-u", Description: "Target URL with parameter"},
				{Name: "level", Type: "int", Required: false, Default: "3", Flag: "--level", Description: "Test level (1-5)"},
				{Name: "risk", Type: "int", Required: false, Default: "2", Flag: "--risk", Description: "Risk level (1-3)"},
				{Name: "batch", Type: "bool", Required: false, Default: true, Flag: "--batch", Description: "Non-interactive mode"},
				{Name: "dbs", Type: "bool", Required: false, Default: false, Flag: "--dbs", Description: "Enumerate DBs"},
				{Name: "dump", Type: "bool", Required: false, Default: false, Flag: "--dump", Description: "Dump table data"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"sqli", "injection", "database"}, RiskLevel: "high", Timeout: 30 * time.Minute,
		},
		{
			ID: "metasploit", Name: "Metasploit Framework",
			Description: "Exploitation framework (runs msfconsole -q -x with an assembled resource script)",
			Category:    "exploit", Version: "6.3", Command: "msfconsole",
			FixedArgs:    []string{"-q", "-x"},
			ArgsTemplate: "use {{.exploit}}; set RHOSTS {{.rhosts}};{{if .rport}} set RPORT {{.rport}};{{end}}{{if .payload}} set PAYLOAD {{.payload}};{{end}} run; exit",
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
			Category:    "post", Version: "2.4", Command: "linpeas.sh",
			Parameters:  []ToolParameter{},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"privilege-escalation", "linux", "enumeration"}, RiskLevel: "high", Timeout: 15 * time.Minute,
		},
		{
			ID: "winpeas", Name: "WinPEAS",
			Description: "Windows privilege escalation checker",
			Category:    "post", Version: "2.3", Command: "winPEASx64.exe",
			Parameters:  []ToolParameter{},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"privilege-escalation", "windows", "enumeration"}, RiskLevel: "high", Timeout: 15 * time.Minute,
		},

		// === NETWORK ===
		{
			ID: "responder", Name: "Responder",
			Description: "LLMNR/NTLM poisoning tool",
			Category:    "network", Version: "3.1.0.0", Command: "Responder",
			Parameters: []ToolParameter{
				{Name: "interface", Type: "string", Required: true, Description: "Network interface"},
			},
			Tags: []string{"llmnr", "ntlm", "poisoning"}, RiskLevel: "high", Timeout: 0,
		},
		{
			ID: "tcpdump-capture", Name: "TCPDump",
			Description: "Network packet capture",
			Category:    "network", Version: "4.99", Command: "tcpdump",
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
			Category:    "forensic", Version: "3.0", Command: "vol",
			Parameters: []ToolParameter{
				{Name: "memory-file", Type: "file", Required: true, Flag: "-f", Description: "Memory dump file"},
				{Name: "profile", Type: "string", Required: false, Description: "OS profile"},
				{Name: "plugin", Type: "string", Required: false, Default: "pslist", Description: "Plugin to run"},
			},
			Tags: []string{"memory", "forensics", "analysis"}, RiskLevel: "low", Timeout: 30 * time.Minute,
		},

		// === CLOUD ===
		{
			ID: "scout-suite", Name: "Scout Suite",
			Description: "Cloud security auditor",
			Category:    "cloud", Version: "0.39", Command: "scout",
			Parameters: []ToolParameter{
				{Name: "provider", Type: "select", Required: true, Options: []string{"aws", "azure", "gcp"}, Description: "Cloud provider"},
				{Name: "profile", Type: "string", Required: true, Description: "Profile name"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"cloud", "audit", "aws", "azure", "gcp"}, RiskLevel: "low", Timeout: 15 * time.Minute,
		},

		// === FAST PORT SCANNING ===
		{
			ID: "rustscan-scan", Name: "RustScan",
			Description: "Ultra-fast TCP port scanner (auto-feeds found ports into nmap service detection)",
			Category:    "scan", Version: "2.3", Command: "rustscan",
			Parameters: []ToolParameter{
				{Name: "target", Type: "ip", Required: true, Flag: "-a", Description: "Target IP or CIDR"},
				{Name: "ports", Type: "string", Required: false, Default: "", Flag: "-p", Description: "Port range (e.g. 1-65535); empty scans top ports"},
				{Name: "ulimit", Type: "int", Required: false, Default: "5000", Flag: "--ulimit", Description: "Open file descriptor limit (throughput)"},
				{Name: "timeout", Type: "int", Required: false, Default: "1500", Flag: "-t", Description: "Per-port timeout in ms"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"network", "ports", "fast-scan"}, RiskLevel: "low", Timeout: 10 * time.Minute,
		},
		{
			ID: "masscan-scan", Name: "Masscan",
			Description: "Mass IP port scanner (asynchronous SYN scan, internet-scale)",
			Category:    "scan", Version: "1.3", Command: "masscan",
			Parameters: []ToolParameter{
				{Name: "target", Type: "ip", Required: true, Description: "Target IP or CIDR"},
				{Name: "ports", Type: "string", Required: false, Default: "1-10000", Flag: "-p", Description: "Port range"},
				{Name: "rate", Type: "int", Required: false, Default: "1000", Flag: "--rate", Description: "Packets per second"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"network", "ports", "fast-scan", "syn"}, RiskLevel: "medium", Timeout: 15 * time.Minute,
		},

		// === SERVICE-SPECIFIC ENUMERATION ===
		{
			ID: "smtp-user-enum", Name: "SMTP User Enumerator",
			Description: "Enumerate OS-level user accounts on SMTP servers via VRFY/EXPN/RCPT",
			Category:    "network", Version: "0.2", Command: "smtp-user-enum",
			Parameters: []ToolParameter{
				{Name: "mode", Type: "select", Required: false, Default: "VRFY", Options: []string{"VRFY", "EXPN", "RCPT"}, Flag: "-M", Description: "Enumeration method"},
				{Name: "users", Type: "file", Required: false, Flag: "-U", Description: "Username wordlist file"},
				{Name: "host", Type: "ip", Required: true, Flag: "-t", Description: "SMTP server host"},
				{Name: "port", Type: "int", Required: false, Default: "25", Flag: "-p", Description: "SMTP port"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"smtp", "enumeration", "users"}, RiskLevel: "low", Timeout: 10 * time.Minute,
		},
		{
			ID: "onesixtyone-scan", Name: "onesixtyone (SNMP brute)",
			Description: "Fast SNMP community string brute-forcer",
			Category:    "network", Version: "0.7", Command: "onesixtyone",
			Parameters: []ToolParameter{
				{Name: "target", Type: "ip", Required: true, Description: "Target host"},
				{Name: "communities", Type: "file", Required: false, Flag: "-c", Description: "Community string wordlist"},
				{Name: "port", Type: "int", Required: false, Default: "161", Flag: "-p", Description: "SNMP port"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"snmp", "brute-force", "enumeration"}, RiskLevel: "low", Timeout: 10 * time.Minute,
		},
		{
			ID: "snmpwalk-enum", Name: "snmpwalk",
			Description: "Walk the SNMP MIB tree of a host (requires a valid community string, e.g. from onesixtyone)",
			Category:    "network", Version: "5.9", Command: "snmpwalk",
			Parameters: []ToolParameter{
				{Name: "version", Type: "select", Required: false, Default: "2c", Options: []string{"1", "2c", "3"}, Flag: "-v", Description: "SNMP version"},
				{Name: "community", Type: "string", Required: false, Default: "public", Flag: "-c", Description: "Community string"},
				{Name: "target", Type: "ip", Required: true, Description: "Target host"},
				{Name: "oid", Type: "string", Required: false, Default: ".1.3.6.1.2.1.1", Description: "OID subtree to walk"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"snmp", "enumeration", "mib"}, RiskLevel: "low", Timeout: 10 * time.Minute,
		},

		// === ACTIVE DIRECTORY / IMPACKET ===
		{
			ID: "impacket-secretsdump", Name: "Impacket secretsdump.py",
			Description: "Remotely dump SAM/NTDS.dit/LSA secrets via DRSUAPI (needs valid credentials or hash)",
			Category:    "exploit", Version: "0.12", Command: "impacket-secretsdump",
			Parameters: []ToolParameter{
				{Name: "target", Type: "string", Required: true, Description: "domain/user:password@host (or domain/user@host with -hashes)"},
				{Name: "hashes", Type: "string", Required: false, Flag: "-hashes", Description: "NTLM hash LM:NT format"},
				{Name: "just-dc", Type: "bool", Required: false, Default: false, Flag: "-just-dc", Description: "Only dump NTDS.dit (DC only)"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"active-directory", "credentials", "ntlm"}, RiskLevel: "high", Timeout: 30 * time.Minute,
		},
		{
			ID: "impacket-getnpusers", Name: "Impacket GetNPUsers.py",
			Description: "Enumerate and harvest AS-REP roastable users (users without Kerberos preauth)",
			Category:    "exploit", Version: "0.12", Command: "impacket-GetNPUsers",
			Parameters: []ToolParameter{
				{Name: "domain", Type: "domain", Required: true, Description: "Target domain (e.g. corp.local/)"},
				{Name: "usersfile", Type: "file", Required: false, Flag: "-usersfile", Description: "File with candidate usernames"},
				{Name: "dc-host", Type: "string", Required: false, Flag: "-dc-host", Description: "Domain controller host"},
				{Name: "no-pass", Type: "bool", Required: false, Default: true, Flag: "-no-pass", Description: "Do not prompt for password (AS-REP roast)"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"active-directory", "kerberos", "asrep"}, RiskLevel: "medium", Timeout: 15 * time.Minute,
		},
		{
			ID: "bloodhound-collect", Name: "BloodHound Collector",
			Description: "Collect Active Directory graph data (bloodhound-python) for attack-path analysis in neo4j/BloodHound CE",
			Category:    "post", Version: "1.6", Command: "bloodhound-python",
			Parameters: []ToolParameter{
				{Name: "domain", Type: "domain", Required: true, Flag: "-d", Description: "Target domain"},
				{Name: "username", Type: "string", Required: false, Flag: "-u", Description: "Username"},
				{Name: "password", Type: "string", Required: false, Flag: "-p", Description: "Password"},
				{Name: "nameserver", Type: "ip", Required: false, Flag: "-ns", Description: "DNS nameserver (usually the DC)"},
				{Name: "collection", Type: "string", Required: false, Default: "All", Flag: "-c", Description: "Collection methods (Default, All, DCOnly...)"},
				{Name: "zip", Type: "string", Required: false, Flag: "-zip", Description: "Output zip filename"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"active-directory", "graph", "lateral-movement"}, RiskLevel: "low", Timeout: 30 * time.Minute,
		},

		// === PAYLOAD GENERATION ===
		{
			ID: "msfvenom-payload", Name: "MSFvenom Payload Generator",
			Description: "Generate encoded payloads (reverse shells, bind shells, DLLs, executables)",
			Category:    "exploit", Version: "6.3", Command: "msfvenom",
			Parameters: []ToolParameter{
				{Name: "payload", Type: "string", Required: true, Flag: "-p", Description: "Payload (e.g. windows/x64/meterpreter/reverse_tcp)"},
				{Name: "lhost", Type: "ip", Required: true, Flag: "LHOST=", Description: "Callback host (appended as LHOST=<val>)"},
				{Name: "lport", Type: "int", Required: false, Default: "4444", Flag: "LPORT=", Description: "Callback port (appended as LPORT=<val>)"},
				{Name: "format", Type: "string", Required: false, Default: "exe", Flag: "-f", Description: "Output format (exe, dll, psh, elf, raw...)"},
				{Name: "output", Type: "string", Required: false, Flag: "-o", Description: "Output file path"},
				{Name: "encoder", Type: "string", Required: false, Flag: "-e", Description: "Encoder (e.g. x86/shikata_ga_nai)"},
			},
			ParseOutput: false, OutputType: "text",
			Tags: []string{"payload", "meterpreter", "shellcode"}, RiskLevel: "medium", Timeout: 5 * time.Minute,
		},

		// === CLOUD CLIs ===
		{
			ID: "aws-recon", Name: "AWS CLI Recon",
			Description: "Query AWS account identity, regions, IAM users/policies and exposure (aws CLI; credentials must be configured or provided)",
			Category:    "cloud", Version: "2.x", Command: "aws",
			Parameters: []ToolParameter{
				{Name: "service", Type: "string", Required: false, Default: "sts", Description: "AWS service (sts, iam, s3, ec2...)"},
				{Name: "operation", Type: "string", Required: false, Default: "get-caller-identity", Description: "API operation"},
				{Name: "region", Type: "string", Required: false, Flag: "--region", Description: "AWS region"},
				{Name: "output", Type: "select", Required: false, Default: "json", Options: []string{"json", "text", "table"}, Flag: "--output", Description: "Output format"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"cloud", "aws", "recon"}, RiskLevel: "low", Timeout: 5 * time.Minute,
		},
		{
			ID: "az-recon", Name: "Azure CLI Recon",
			Description: "Query Azure subscriptions/resources via az CLI (requires az login credentials)",
			Category:    "cloud", Version: "2.x", Command: "az",
			Parameters: []ToolParameter{
				{Name: "group", Type: "string", Required: false, Default: "account", Description: "Command group (account, resource, vm, network...)"},
				{Name: "operation", Type: "string", Required: false, Default: "show", Description: "Operation (show, list...)"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"cloud", "azure", "recon"}, RiskLevel: "low", Timeout: 5 * time.Minute,
		},
		{
			ID: "gcloud-recon", Name: "GCP CLI Recon",
			Description: "Query GCP projects/compute/IAM via gcloud CLI (requires authenticated account)",
			Category:    "cloud", Version: "4.x", Command: "gcloud",
			Parameters: []ToolParameter{
				{Name: "group", Type: "string", Required: false, Default: "projects", Description: "Command group (projects, compute, iam...)"},
				{Name: "operation", Type: "string", Required: false, Default: "list", Description: "Operation"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"cloud", "gcp", "recon"}, RiskLevel: "low", Timeout: 5 * time.Minute,
		},
		{
			ID: "pacu-recon", Name: "Pacu (AWS exploitation)",
			Description: "AWS exploitation framework — enumerate permissions, escalate privileges, exfiltrate (requires AWS keys)",
			Category:    "cloud", Version: "2.x", Command: "pacu",
			Parameters: []ToolParameter{
				{Name: "session", Type: "string", Required: false, Default: "artex", Description: "Pacu session name"},
				{Name: "module", Type: "string", Required: false, Description: "Module to run (e.g. runall, iam__enum_users)"},
				{Name: "key-alias", Type: "string", Required: false, Description: "Imported key alias"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"cloud", "aws", "exploitation", "privesc"}, RiskLevel: "medium", Timeout: 30 * time.Minute,
		},

		// === CONTAINER & SUPPLY CHAIN ===
		{
			ID: "trivy-scan", Name: "Trivy",
			Description: "Comprehensive container image / filesystem / repo vulnerability scanner (uses Docker socket for image scans)",
			Category:    "container", Version: "0.x", Command: "trivy",
			Parameters: []ToolParameter{
				{Name: "mode", Type: "select", Required: false, Default: "image", Options: []string{"image", "fs", "repo"}, Description: "Scan target type"},
				{Name: "target", Type: "string", Required: true, Description: "Image reference, filesystem path, or repo URL"},
				{Name: "severity", Type: "string", Required: false, Flag: "--severity", Description: "Severity filter (e.g. HIGH,CRITICAL)"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"container", "docker", "cve", "supply-chain"}, RiskLevel: "low", Timeout: 30 * time.Minute,
		},
		{
			ID: "grype-scan", Name: "Grype",
			Description: "Vulnerability scanner for container images and filesystems (SBOM-driven)",
			Category:    "container", Version: "0.x", Command: "grype",
			Parameters: []ToolParameter{
				{Name: "target", Type: "string", Required: true, Description: "Image reference or directory"},
				{Name: "scope", Type: "select", Required: false, Default: "squashed", Options: []string{"squashed", "all-layers"}, Flag: "--scope", Description: "Scan scope"},
			},
			ParseOutput: true, OutputType: "text",
			Tags: []string{"container", "cve", "sbom"}, RiskLevel: "low", Timeout: 30 * time.Minute,
		},

		// === SAST ===
		{
			ID: "semgrep-scan", Name: "Semgrep",
			Description: "Static analysis for source code — finds injections, secrets, and insecure patterns (semgrep --config auto)",
			Category:    "sast", Version: "1.x", Command: "semgrep",
			Parameters: []ToolParameter{
				{Name: "target", Type: "file", Required: true, Description: "Source directory or file to scan"},
				{Name: "config", Type: "string", Required: false, Default: "auto", Flag: "--config", Description: "Ruleset (auto, p/owasp-top-ten, p/secrets...)"},
				{Name: "json", Type: "bool", Required: false, Default: true, Flag: "--json", Description: "JSON output"},
			},
			ParseOutput: true, OutputType: "json",
			Tags: []string{"sast", "code", "secrets", "owasp"}, RiskLevel: "low", Timeout: 30 * time.Minute,
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
