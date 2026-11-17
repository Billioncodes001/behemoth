// Package agent implements a tool catalog system inspired by NukeRat's Armory.
// It provides a registry of security tools, BOFs, and utilities with metadata.
package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ---------- Types ----------

// ToolType represents the type of tool.
type ToolType string

const (
	ToolBOF       ToolType = "bof"        // Beacon Object File
	ToolDotNET    ToolType = "dotnet"     // .NET assembly
	ToolScript    ToolType = "script"     // PowerShell/Bash script
	ToolBinary    ToolType = "binary"     // Compiled binary
	ToolLOLBAS    ToolType = "lolbas"     // Living off the Land
	ToolCustom    ToolType = "custom"     // Custom tool
)

// ParseMode represents how to parse tool output.
type ParseMode string

const (
	ParseNone      ParseMode = "none"
	ParseNormalize  ParseMode = "normalize"
	ParsePositional ParseMode = "positional"
	ParseCustom     ParseMode = "custom"
	ParseJSON       ParseMode = "json"
)

// ArgType represents argument types.
type ArgType string

const (
	ArgString   ArgType = "Z" // Null-terminated string
	ArgWString  ArgType = "z" // Wide string
	ArgInt      ArgType = "i" // Integer
	ArgBytes    ArgType = "b" // Byte array
	ArgBool     ArgType = "B" // Boolean
)

// ToolArg defines a tool argument.
type ToolArg struct {
	Name        string  `json:"name"`
	Type        ArgType `json:"type"`
	Required    bool    `json:"required"`
	Positional  bool    `json:"positional,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Description string  `json:"description,omitempty"`
}

// ToolCategory represents a tool category.
type ToolCategory string

const (
	CatRecon       ToolCategory = "recon"
	CatEnumeration ToolCategory = "enumeration"
	CatPrivEsc     ToolCategory = "privilege_escalation"
	CatLateral     ToolCategory = "lateral_movement"
	CatExfil       ToolCategory = "exfiltration"
	CatPersistence ToolCategory = "persistence"
	CatEvasion     ToolCategory = "evasion"
	CatCredential  ToolCategory = "credential_access"
	CatExecution   ToolCategory = "execution"
	CatDiscovery   ToolCategory = "discovery"
)

// Tool represents a single tool in the armory.
type Tool struct {
	ID          int64         `json:"id"`
	Name        string        `json:"name"`
	Type        ToolType      `json:"type"`
	Category    ToolCategory  `json:"category"`
	Description string        `json:"description,omitempty"`
	Args        map[string]ToolArg `json:"args,omitempty"`
	ParseMode   ParseMode     `json:"parse"`
	Tags        []string      `json:"tags,omitempty"`
	Platform    string        `json:"platform,omitempty"` // windows, linux, macos, any
	Version     string        `json:"version,omitempty"`
	Author      string        `json:"author,omitempty"`
	Enabled     bool          `json:"enabled"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ToolFilter defines filters for tool queries.
type ToolFilter struct {
	Type     ToolType     `json:"type,omitempty"`
	Category ToolCategory `json:"category,omitempty"`
	Platform string       `json:"platform,omitempty"`
	Tag      string       `json:"tag,omitempty"`
	Enabled  *bool        `json:"enabled,omitempty"`
	Search   string       `json:"search,omitempty"` // Name/description search
	Limit    int          `json:"limit,omitempty"`
}

// ArmoryStats contains statistics about the armory.
type ArmoryStats struct {
	Total    int              `json:"total"`
	ByType   map[ToolType]int `json:"by_type"`
	ByCat    map[ToolCategory]int `json:"by_category"`
	Enabled  int              `json:"enabled"`
	Disabled int              `json:"disabled"`
}

// ---------- Registry ----------

// Registry manages the tool catalog.
type Registry struct {
	mu      sync.RWMutex
	tools   map[int64]*Tool
	byName  map[string]int64
	nextID  int64
	config  RegistryConfig
}

// RegistryConfig holds registry configuration.
type RegistryConfig struct {
	MaxTools int `json:"max_tools"`
}

// NewRegistry creates a new armory registry.
func NewRegistry(config RegistryConfig) *Registry {
	if config.MaxTools == 0 { config.MaxTools = 10000 }
	r := &Registry{
		tools:  make(map[int64]*Tool),
		byName: make(map[string]int64),
		config: config,
	}
	// Load built-in tools
	r.loadBuiltinTools()
	return r
}

// Register adds or updates a tool in the registry.
func (r *Registry) Register(tool *Tool) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.config.MaxTools > 0 && len(r.tools) >= r.config.MaxTools {
		return 0, fmt.Errorf("armory is full (max %d tools)", r.config.MaxTools)
	}

	if existingID, ok := r.byName[tool.Name]; ok {
		// Update existing
		tool.ID = existingID
		r.tools[existingID] = tool
		return existingID, nil
	}

	tool.ID = r.nextID
	r.nextID++
	if !tool.Enabled { tool.Enabled = true } // Default to enabled
	r.tools[tool.ID] = tool
	r.byName[tool.Name] = tool.ID
	return tool.ID, nil
}

// Get retrieves a tool by ID.
func (r *Registry) Get(id int64) *Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tools[id]
}

// GetByName retrieves a tool by name.
func (r *Registry) GetByName(name string) *Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byName[name]
	if !ok { return nil }
	return r.tools[id]
}

// Query retrieves tools matching the filter.
func (r *Registry) Query(filter ToolFilter) []*Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []*Tool
	for _, t := range r.tools {
		if filter.Type != "" && t.Type != filter.Type { continue }
		if filter.Category != "" && t.Category != filter.Category { continue }
		if filter.Platform != "" && t.Platform != filter.Platform && t.Platform != "any" { continue }
		if filter.Enabled != nil && t.Enabled != *filter.Enabled { continue }
		if filter.Search != "" {
			if !containsIgnoreCase(t.Name, filter.Search) && !containsIgnoreCase(t.Description, filter.Search) {
				continue
			}
		}
		if filter.Tag != "" {
			found := false
			for _, tag := range t.Tags {
				if tag == filter.Tag { found = true; break }
			}
			if !found { continue }
		}
		results = append(results, t)
		if filter.Limit > 0 && len(results) >= filter.Limit { break }
	}
	return results
}

// GetAll returns all tools.
func (r *Registry) GetAll() []*Tool { return r.Query(ToolFilter{}) }

// Enable enables a tool by ID.
func (r *Registry) Enable(id int64) error { return r.setEnabled(id, true) }

// Disable disables a tool by ID.
func (r *Registry) Disable(id int64) error { return r.setEnabled(id, false) }

// Stats returns armory statistics.
func (r *Registry) Stats() ArmoryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := ArmoryStats{
		Total:  len(r.tools),
		ByType: make(map[ToolType]int),
		ByCat:  make(map[ToolCategory]int),
	}
	for _, t := range r.tools {
		stats.ByType[t.Type]++
		stats.ByCat[t.Category]++
		if t.Enabled { stats.Enabled++ } else { stats.Disabled++ }
	}
	return stats
}

// ToJSON exports the catalog as JSON.
func (r *Registry) ToJSON() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var tools []*Tool
	for _, t := range r.tools { tools = append(tools, t) }
	return json.Marshal(tools)
}

// FromJSON imports tools from JSON (NukeRat format compatible).
func (r *Registry) FromJSON(data []byte) (int, error) {
	var tools []struct {
		Name  string                   `json:"name"`
		Type  string                   `json:"type"`
		Args  map[string]interface{}   `json:"args"`
		Parse string                   `json:"parse"`
	}
	if err := json.Unmarshal(data, &tools); err != nil { return 0, err }

	count := 0
	for _, t := range tools {
		tool := &Tool{
			Name:      t.Name,
			Type:      ToolType(t.Type),
			ParseMode: ParseMode(t.Parse),
			Args:      convertArgs(t.Args),
			Enabled:   true,
		}
		if _, err := r.Register(tool); err == nil { count++ }
	}
	return count, nil
}

// ---------- Internal Methods ----------

func (r *Registry) setEnabled(id int64, enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tool, ok := r.tools[id]
	if !ok { return fmt.Errorf("tool not found") }
	tool.Enabled = enabled
	return nil
}

func (r *Registry) loadBuiltinTools() {
	builtins := []Tool{
		{Name: "port-scan", Type: ToolScript, Category: CatRecon, Description: "TCP port scanner", ParseMode: ParseJSON, Tags: []string{"recon", "network"}, Platform: "any"},
		{Name: "enum-smb", Type: ToolBOF, Category: CatEnumeration, Description: "Enumerate SMB shares", ParseMode: ParseJSON, Tags: []string{"enumeration", "windows", "smb"}, Platform: "windows"},
		{Name: "hashdump", Type: ToolBOF, Category: CatCredential, Description: "Dump local password hashes", ParseMode: ParseJSON, Tags: []string{"credential", "windows"}, Platform: "windows"},
		{Name: "mimikatz", Type: ToolDotNET, Category: CatCredential, Description: "Extract plaintext credentials from memory", ParseMode: ParseCustom, Tags: []string{"credential", "windows", "memory"}, Platform: "windows"},
		{Name: "screen-capture", Type: ToolBOF, Category: CatDiscovery, Description: "Capture desktop screenshot", ParseMode: ParseNone, Tags: []string{"discovery", "surveillance"}, Platform: "any"},
		{Name: "keylogger", Type: ToolBOF, Category: CatCredential, Description: "Log keystrokes", ParseMode: ParseNone, Tags: []string{"credential", "surveillance"}, Platform: "windows"},
		{Name: "psexec", Type: ToolBOF, Category: CatLateral, Description: "Execute remote commands via SMB", ParseMode: ParsePositional, Tags: []string{"lateral", "smb", "windows"}, Platform: "windows"},
		{Name: "wmi-exec", Type: ToolLOLBAS, Category: CatLateral, Description: "Execute via WMI (LOLBAS)", ParseMode: ParsePositional, Tags: []string{"lateral", "lolbas", "wmi"}, Platform: "windows"},
		{Name: "shell-netcat", Type: ToolLOLBAS, Category: CatLateral, Description: "Reverse shell via netcat", ParseMode: ParseNone, Tags: []string{"lateral", "lolbas"}, Platform: "any"},
		{Name: "priv-whoami", Type: ToolLOLBAS, Category: CatPrivEsc, Description: "Check current privileges", ParseMode: ParseNormalize, Tags: []string{"privesc", "lolbas"}, Platform: "windows"},
	}
	for _, t := range builtins {
		t.Enabled = true
		r.tools[r.nextID] = &t
		r.byName[t.Name] = r.nextID
		r.nextID++
	}
}

// ---------- Utility Functions ----------

func containsIgnoreCase(s, sub string) bool {
	sLower := strings.ToLower(s)
	subLower := strings.ToLower(sub)
	return strings.Contains(sLower, subLower)
}

func convertArgs(raw map[string]interface{}) map[string]ToolArg {
	if raw == nil { return nil }
	args := make(map[string]ToolArg)
	for k, v := range raw {
		if m, ok := v.(map[string]interface{}); ok {
			arg := ToolArg{}
			if n, ok := m["name"].(string); ok { arg.Name = n }
			if t, ok := m["type"].(string); ok { arg.Type = ArgType(t) }
			if r, ok := m["required"].(bool); ok { arg.Required = r }
			if p, ok := m["positional"].(bool); ok { arg.Positional = p }
			if d, ok := m["default"]; ok { arg.Default = d }
			args[k] = arg
		}
	}
	return args
}

// ListCategories returns all available categories.
func ListCategories() []ToolCategory {
	cats := []ToolCategory{CatRecon, CatEnumeration, CatPrivEsc, CatLateral, CatExfil, CatPersistence, CatEvasion, CatCredential, CatExecution, CatDiscovery}
	sort.Slice(cats, func(i, j int) bool { return cats[i] < cats[j] })
	return cats
}