package tools

import (
	"sync"
	"time"
)

// Category represents an attack category (inspired by HexStrike's taxonomy).
type Category struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tools       []string `json:"tools"` // Tool IDs in this category
}

// Built-in attack categories.
var Categories = []Category{
	{ID: "recon", Name: "Reconnaissance", Description: "Information gathering and OSINT", Tools: []string{"nmap-scan", "subfinder", "httpx-probe", "theHarvester"}},
	{ID: "scan", Name: "Scanning", Description: "Port and vulnerability scanning", Tools: []string{"nmap-scan", "nuclei-scan", "nikto-scan"}},
	{ID: "web", Name: "Web Application", Description: "Web app testing and analysis", Tools: []string{"dirb-scan", "gobuster-scan", "sqlmap-inject", "ffuf-fuzz"}},
	{ID: "exploit", Name: "Exploitation", Description: "Vulnerability exploitation", Tools: []string{"metasploit", "sqlmap-inject", "searchsploit"}},
	{ID: "post", Name: "Post-Exploitation", Description: "Post-exploitation activities", Tools: []string{"linpeas", "winpeas", "mimikatz"}},
	{ID: "network", Name: "Network", Description: "Network protocol analysis", Tools: []string{"wireshark-capture", "responder", "bettercap"}},
	{ID: "wireless", Name: "Wireless", Description: "WiFi/Bluetooth testing", Tools: []string{"aircrack-ng", "wifite", "bluetooth-scanner"}},
	{ID: "forensic", Name: "Forensics", Description: "Digital forensics", Tools: []string{"autopsy", "volatility", "binwalk"}},
	{ID: "cloud", Name: "Cloud", Description: "Cloud security testing", Tools: []string{"scout-suite", "cloudmapper", "pacu"}},
	{ID: "mobile", Name: "Mobile", Description: "Mobile app security", Tools: []string{"mobsf", "frida", "objection"}},
}

// Tool defines a security tool in the catalog (HexStrike-inspired).
type Tool struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Version     string            `json:"version"`
	
	// Execution
	Command     string            `json:"command"`               // Base command
	ArgsTemplate string           `json:"args_template,omitempty"` // Go template for args
	
	// Parameters
	Parameters  []ToolParameter   `json:"parameters"`
	
	// Output handling
	ParseOutput bool              `json:"parse_output"`
	OutputType  string            `json:"output_type"` // json, text, xml, csv
	
	// Metadata
	RiskLevel   string            `json:"risk_level"` // low, medium, high, critical
	Tags        []string          `json:"tags"`
	Requires    []string          `json:"requires"`   // Required binaries
	Examples    []ToolExample     `json:"examples"`
	
	// Timing
	Timeout     time.Duration     `json:"timeout"`
}

// ToolParameter is a tool parameter definition.
type ToolParameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"` // string, int, bool, file, select, ip, url, domain
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Description string      `json:"description"`
	Options     []string    `json:"options,omitempty"`
	Flag        string      `json:"flag,omitempty"` // CLI flag (e.g., "-p")
}

// ToolExample is an example usage.
type ToolExample struct {
	Command string            `json:"command"`
	Params  map[string]string `json:"params"`
	Output  string            `json:"output,omitempty"`
}

// ToolCatalog manages the collection of available tools.
type Catalog struct {
	mu     sync.RWMutex
	tools  map[string]*Tool
	cats   map[string]*Category
}

// NewCatalog creates a new tool catalog with built-in tools.
func NewCatalog() *Catalog {
	c := &Catalog{
		tools: make(map[string]*Tool),
		cats:  make(map[string]*Category),
	}
	
	// Register categories
	for i := range Categories {
		c.cats[Categories[i].ID] = &Categories[i]
	}
	
	// Register built-in tools
	c.registerBuiltInTools()
	
	return c
}

// Get returns a tool by ID.
func (c *Catalog) Get(id string) (*Tool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.tools[id]
	return t, ok
}

// List returns all tools.
func (c *Catalog) List() []*Tool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*Tool, 0, len(c.tools))
	for _, t := range c.tools {
		result = append(result, t)
	}
	return result
}

// ByCategory returns tools in a category.
func (c *Catalog) ByCategory(cat string) []*Tool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var result []*Tool
	for _, t := range c.tools {
		if t.Category == cat {
			result = append(result, t)
		}
	}
	return result
}

// Categories returns all categories.
func (c *Catalog) Categories() []*Category {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*Category, 0, len(c.cats))
	for _, cat := range c.cats {
		result = append(result, cat)
	}
	return result
}

// Search searches tools by name, description, or tags.
func (c *Catalog) Search(query string) []*Tool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var results []*Tool
	for _, t := range c.tools {
		if matchTool(t, query) {
			results = append(results, t)
		}
	}
	return results
}

// Count returns the number of tools.
func (c *Catalog) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.tools)
}

// Add registers a new tool.
func (c *Catalog) Add(tool *Tool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tools[tool.ID] = tool
}

func matchTool(t *Tool, q string) bool {
	if containsStr(t.Name, q) || containsStr(t.Description, q) || containsStr(t.ID, q) {
		return true
	}
	for _, tag := range t.Tags {
		if containsStr(tag, q) {
			return true
		}
	}
	return false
}

func containsStr(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}