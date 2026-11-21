package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// 平台操作工具(给内置 Auto agent 用):建/改 skill、自定义工具、MCP。都是 host 工具,
// seed 进 tools 表、默认绑定 auto,经 hostTools 注入。复用现有 db/文件系统逻辑。

func (s *Server) platformTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolCreateSkill(),
		s.toolUpdateSkillFile(),
		s.toolCreateCustomTool(),
		s.toolUpdateCustomTool(),
		s.toolCreateMCP(),
		s.toolUpdateMCP(),
		s.toolDeleteAssetsByHost(),
		s.toolListInterceptRules(),
		s.toolUpdateInterceptRule(),
	}
}

// platformToolKeys are the tool keys the Auto agent gets bound by default.
var platformToolKeys = []string{
	"create_skill", "update_skill_file",
	"create_custom_tool", "update_custom_tool",
	"create_mcp", "update_mcp",
	"delete_assets_by_host",
	"list_intercept_rules", "update_intercept_rule",
}

// ---- assets ----

// toolDeleteAssetsByHost hard-deletes every asset tied to one host (exact match).
// Platform-level (not a per-task tool): operates on the global, cross-task asset库.
func (s *Server) toolDeleteAssetsByHost() actool.CoreTool {
	return wrTool("delete_assets_by_host",
		"Precisely delete assets by host: deletes the domain/subdomain of that host along with all services and endpoints under it.\n"+
			"Exact host match (lowercased and trimmed), not fuzzy or wildcard.\n"+
			"Passing a root domain (e.g. example.com) also deletes its subdomains and their services/endpoints; passing a subdomain (e.g. a.example.com) or IP deletes only that host itself and its services/endpoints.\n"+
			"⚠️ Hard delete operating on the global asset database (shared across tasks) and cannot be undone.",
		objSchema(map[string]any{
			"host": strParam("Host to delete: domain / subdomain / IP. Exact match, e.g. example.com, a.example.com, or 1.2.3.4"),
		}, "host"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			as := s.assetStore()
			if as == nil {
				return actool.Errorf("asset store not initialized"), nil
			}
			var a struct {
				Host string `json:"host"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Host) == "" {
				return actool.Errorf("host cannot be empty"), nil
			}
			counts, err := as.DeleteByHost(a.Host)
			if err != nil {
				return actool.Errorf("delete failed: " + err.Error()), nil
			}
			var total int64
			for _, n := range counts {
				total += n
			}
			return jsonResult(map[string]any{
				"host":            a.Host,
				"deleted":         total,
				"deleted_by_type": counts,
			})
		})
}

// ---- skills ----

func (s *Server) toolCreateSkill() actool.CoreTool {
	return wrTool("create_skill",
		"Create a new skill (writes SKILL.md following the agentskills.io specification). name must use lowercase letters, digits, and hyphens.",
		objSchema(map[string]any{
			"name":         strParam("Skill name (starts with a lowercase letter; lowercase letters, digits, and hyphens only)"),
			"description":  strParam("Skill description (required; explains what it does and when to use it)"),
			"instructions": strParam("Markdown body instructions (optional)"),
		}, "name", "description"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Name, Description, Instructions string }
			_ = json.Unmarshal(in, &a)
			if !validSkillName(a.Name) {
				return actool.Errorf("invalid skill name (must start with a lowercase letter, contain only lowercase letters/digits/hyphens, <= 64 chars)"), nil
			}
			if strings.TrimSpace(a.Description) == "" {
				return actool.Errorf("description is required"), nil
			}
			path := filepath.Join(s.skillDir, a.Name)
			if _, err := os.Stat(path); err == nil {
				return actool.Errorf("skill already exists: " + a.Name), nil
			}
			if err := os.MkdirAll(path, 0o755); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			b.WriteString("---\n")
			fmt.Fprintf(&b, "name: %s\n", a.Name)
			fmt.Fprintf(&b, "description: %s\n", a.Description)
			b.WriteString("---\n")
			if strings.TrimSpace(a.Instructions) != "" {
				b.WriteString(a.Instructions)
			} else {
				fmt.Fprintf(&b, "## %s\n\n1. \n2. \n3. \n", a.Name)
			}
			if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte(b.String()), 0o644); err != nil {
				_ = os.RemoveAll(path)
				return actool.Errorf(err.Error()), nil
			}
			if s.m != nil && s.m.pg != nil {
				for _, agKey := range []string{"auto", "pentest", "worker"} {
					if ag, err := s.m.pg.GetAgentByKey(agKey); err == nil && ag != nil {
						_, _ = s.m.pg.Exec(`INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled) VALUES($1, $2, true) ON CONFLICT (agent_id, skill_name) DO UPDATE SET enabled=true`, ag.ID, a.Name)
					}
				}
			}
			log.Printf("[skills] Created and enabled skill %q for auto, pentest, and worker", a.Name)
			return actool.Text("skill created and enabled for operational agents: " + a.Name), nil
		})
}

func (s *Server) toolUpdateSkillFile() actool.CoreTool {
	return wrTool("update_skill_file",
		"Write or overwrite a file inside a skill (defaults to SKILL.md). Used to modify skill content or add scripts/references.",
		objSchema(map[string]any{
			"name":    strParam("Skill name"),
			"file":    strParam("Relative path (optional, defaults to SKILL.md, e.g. scripts/run.py)"),
			"content": strParam("Full file content"),
		}, "name", "content"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Name, File, Content string }
			_ = json.Unmarshal(in, &a)
			if !validSkillName(a.Name) {
				return actool.Errorf("invalid skill name"), nil
			}
			skillPath := filepath.Join(s.skillDir, a.Name)
			if _, err := os.Stat(skillPath); os.IsNotExist(err) {
				return actool.Errorf("skill does not exist: " + a.Name), nil
			}
			rel := strings.TrimSpace(a.File)
			if rel == "" {
				rel = "SKILL.md"
			}
			clean, msg := skillRelPath(rel)
			if msg != "" {
				return actool.Errorf("invalid path: " + msg), nil
			}
			full := filepath.Join(skillPath, clean)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err := os.WriteFile(full, []byte(a.Content), 0o644); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("skill file written: " + a.Name + "/" + clean), nil
		})
}

// ---- custom tools ----

type customToolToolInput struct {
	Key         string          `json:"key"`
	Description string          `json:"description"`
	Kind        string          `json:"kind"`
	Exec        json.RawMessage `json:"exec"`
	Schema      json.RawMessage `json:"schema"`
	Agents      []string        `json:"agents"`
	Deferred    bool            `json:"deferred"`
	Enabled     *bool           `json:"enabled"`
}

func customToolSchema(keyDesc string) map[string]any {
	return objSchema(map[string]any{
		"key":         strParam(keyDesc),
		"description": strParam("Description shown to the model"),
		"kind":        strParam("shell | command | script (Python only) | http. shell = bash environment declaration (informs the model that the tool can be invoked directly in bash, no exec/schema needed); the other three require exec"),
		"exec":        map[string]any{"type": "object", "description": "Execution spec (not needed for shell kind): command -> {command}; script -> {code}; http -> {method,url,headers,body,proxy,use_recording_proxy}"},
		"schema":      map[string]any{"type": "object", "description": "Parameter JSON-Schema (optional for shell/command/script; required with properties for http)"},
		"agents":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Bound agent keys (optional)"},
		"deferred":    map[string]any{"type": "boolean", "description": "Whether to defer schema loading (ignored for shell kind; enable only for infrequently used command/script/http tools)"},
		"enabled":     map[string]any{"type": "boolean", "description": "Whether enabled (default true)"},
	}, "key", "kind")
}

func toDBTool(a customToolToolInput) *db.Tool {
	enabled := true
	if a.Enabled != nil {
		enabled = *a.Enabled
	}
	agents := a.Agents
	if len(agents) == 0 {
		agents = []string{"auto", "pentest", "worker"}
	}
	return &db.Tool{
		Key: a.Key, Description: a.Description, Schema: a.Schema, Agents: agents,
		Enabled: enabled, Kind: a.Kind, Exec: a.Exec, Deferred: a.Deferred,
	}
}

func (s *Server) toolCreateCustomTool() actool.CoreTool {
	return wrTool("create_custom_tool", "[Important] When installing tools not built into the platform, call this tool to register them so the platform and agents can invoke them! Creates a custom tool (shell/command/script/http). shell = bash environment declaration requiring only key + description + agents (no exec/schema needed).",
		customToolSchema("Tool key (starts with a lowercase letter; lowercase letters, digits, and underscores only)"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a customToolToolInput
			_ = json.Unmarshal(in, &a)
			a.Key = strings.TrimSpace(a.Key)
			if !reToolKey.MatchString(a.Key) {
				return actool.Errorf("key must start with a lowercase letter and contain only lowercase letters, digits, and underscores"), nil
			}
			if a.Kind != "shell" && a.Kind != "command" && a.Kind != "script" && a.Kind != "http" {
				return actool.Errorf("kind must be shell / command / script / http"), nil
			}
			if a.Kind == "http" && !hasSchemaProps(a.Schema) {
				return actool.Errorf("http tools must provide a parameter JSON Schema (cannot be empty)"), nil
			}
			if exist, _ := s.m.pg.GetTool(a.Key); exist != nil {
				return actool.Errorf("key already exists: " + a.Key), nil
			}
			if err := s.m.pg.CreateCustomTool(toDBTool(a)); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("custom tool created: " + a.Key), nil
		})
}

func (s *Server) toolUpdateCustomTool() actool.CoreTool {
	return wrTool("update_custom_tool", "Modify an existing custom tool (by key).",
		customToolSchema("Custom tool key to modify"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a customToolToolInput
			_ = json.Unmarshal(in, &a)
			existing, _ := s.m.pg.GetTool(a.Key)
			if existing == nil || existing.System {
				return actool.Errorf("can only modify custom tools: " + a.Key), nil
			}
			if a.Kind != "shell" && a.Kind != "command" && a.Kind != "script" && a.Kind != "http" {
				return actool.Errorf("kind must be shell / command / script / http"), nil
			}
			if a.Kind == "http" && !hasSchemaProps(a.Schema) {
				return actool.Errorf("http tools must provide a parameter JSON Schema (cannot be empty)"), nil
			}
			if err := s.m.pg.UpdateCustomTool(toDBTool(a)); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("custom tool updated: " + a.Key), nil
		})
}

// ---- MCP ----

type mcpToolInput struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	Transport string          `json:"transport"`
	Command   string          `json:"command"`
	Args      json.RawMessage `json:"args"`
	Env       json.RawMessage `json:"env"`
	URL       string          `json:"url"`
	Enabled   *bool           `json:"enabled"`
	Insecure  *bool           `json:"insecure"`
}

func mcpSchema(withID bool) map[string]any {
	props := map[string]any{
		"name":      strParam("MCP server name"),
		"transport": strParam("stdio | http / sse"),
		"command":   strParam("Launch command for stdio (e.g. npx)"),
		"args":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Command arguments array"},
		"env":       map[string]any{"type": "object", "description": "Environment variables {KEY:VALUE}"},
		"url":       strParam("URL for http/sse"),
		"enabled":   map[string]any{"type": "boolean", "description": "Whether enabled (default true)"},
		"insecure":  map[string]any{"type": "boolean", "description": "http: skip TLS certificate verification (set true for self-signed certs, default false)"},
	}
	required := []string{"name", "transport"}
	if withID {
		props["id"] = map[string]any{"type": "integer", "description": "MCP server id to modify"}
		required = []string{"id", "name", "transport"}
	}
	return objSchema(props, required...)
}

func (a mcpToolInput) toDB() *db.MCPServer {
	enabled := true
	if a.Enabled != nil {
		enabled = *a.Enabled
	}
	insecure := false
	if a.Insecure != nil {
		insecure = *a.Insecure
	}
	return &db.MCPServer{
		ID: a.ID, Name: a.Name, Transport: a.Transport, Command: a.Command,
		Args: a.Args, Env: a.Env, URL: a.URL, Enabled: enabled, Insecure: insecure,
	}
}

func (s *Server) toolCreateMCP() actool.CoreTool {
	return wrTool("create_mcp", "Create and install an MCP server (stdio/http/sse), automatically discover its tools, and authorize visibility for operational agents (auto, pentest, worker, mainagent, reporter).",
		mcpSchema(false),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a mcpToolInput
			_ = json.Unmarshal(in, &a)
			a.ID = 0
			if strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Transport) == "" {
				return actool.Errorf("name / transport are required"), nil
			}
			srv := a.toDB()
			id, err := s.m.pg.SaveMCP(srv)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			srv.ID = id
			for _, agKey := range []string{"auto", "pentest", "worker", "mainagent", "reporter"} {
				if ag, err := s.m.pg.GetAgentByKey(agKey); err == nil && ag != nil {
					_, _ = s.m.pg.Exec(`INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled) VALUES($1, 'mcp', $2, '', true) ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO UPDATE SET enabled=true`, ag.ID, id)
				}
			}
			go func(mcpSrv *db.MCPServer) {
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				if err := s.discoverAndCacheMCP(ctx, mcpSrv); err == nil {
					log.Printf("[mcp] Auto-discovered tools for newly created MCP server %q (id=%d)", mcpSrv.Name, mcpSrv.ID)
				} else {
					log.Printf("[mcp] Tool discovery warning for MCP server %q (id=%d): %v", mcpSrv.Name, mcpSrv.ID, err)
				}
			}(srv)
			return actool.Text(fmt.Sprintf("mcp created, authorized for agents, and discovering tools: id=%d name=%s", id, a.Name)), nil
		})
}

func (s *Server) toolUpdateMCP() actool.CoreTool {
	return wrTool("update_mcp", "Modify an existing MCP server (by id).",
		mcpSchema(true),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a mcpToolInput
			_ = json.Unmarshal(in, &a)
			if a.ID == 0 {
				return actool.Errorf("id is required"), nil
			}
			if _, err := s.m.pg.SaveMCP(a.toDB()); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("mcp updated: id=%d", a.ID)), nil
		})
}

var immutableHostSafetyRuleNames = map[string]bool{
	"[Built-in] Format disk mkfs":                   true,
	"[Built-in] Overwrite disk device dd":           true,
	"[Built-in] Fork bomb":                          true,
	"[Built-in] Shutdown / Reboot":                  true,
	"[Built-in] Kill all processes":                 true,
	"[Built-in] Disk wipe shred / wipe":             true,
	"[Built-in] Flush firewall rules":               true,
	"[Built-in] Destructive system commands":        true,
	"[Built-in] Delete critical system directories": true,
}

func (s *Server) toolListInterceptRules() actool.CoreTool {
	return roTool("list_intercept_rules",
		"List all platform tool-interception rules (IDs, enabled status, regex pattern, action, and message) so you can inspect why a tool call was blocked.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			if s.m == nil || s.m.pg == nil {
				return actool.Errorf("database not initialized"), nil
			}
			rules, err := s.m.pg.ListInterceptRules()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(rules)
		})
}

func (s *Server) toolUpdateInterceptRule() actool.CoreTool {
	return wrTool("update_intercept_rule",
		"Enable, disable, or refine a non-host-OS platform interception rule (by id) when an overly broad rule blocks authorized security reconnaissance or testing. Critical host-OS destructive rules (mkfs, dd, fork bomb, shutdown, system wipe) remain protected.",
		objSchema(map[string]any{
			"id":      map[string]any{"type": "integer", "description": "Interception rule ID from list_intercept_rules"},
			"enabled": map[string]any{"type": "boolean", "description": "Set false to disable or true to enable the rule"},
			"pattern": strParam("Optional updated regex/string pattern (omit to keep current pattern)"),
			"action":  strParam("Optional updated action: allow | ask | deny (omit to keep current action)"),
		}, "id", "enabled"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s.m == nil || s.m.pg == nil {
				return actool.Errorf("database not initialized"), nil
			}
			var a struct {
				ID      int64  `json:"id"`
				Enabled *bool  `json:"enabled"`
				Pattern string `json:"pattern"`
				Action  string `json:"action"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.ID <= 0 || a.Enabled == nil {
				return actool.Errorf("id and enabled (boolean) are required"), nil
			}
			rules, err := s.m.pg.ListInterceptRules()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var target *db.InterceptRule
			for i := range rules {
				if rules[i].ID == a.ID {
					target = &rules[i]
					break
				}
			}
			if target == nil {
				return actool.Errorf(fmt.Sprintf("intercept rule %d not found", a.ID)), nil
			}
			if immutableHostSafetyRuleNames[target.Name] && (!*a.Enabled || strings.TrimSpace(a.Pattern) != "" || (a.Action != "" && a.Action != "deny")) {
				return actool.Errorf(fmt.Sprintf("rule %q protects the ARTEX host operating system and cannot be weakened", target.Name)), nil
			}
			newPattern := target.Pattern
			if strings.TrimSpace(a.Pattern) != "" {
				newPattern = a.Pattern
			}
			newAction := target.Action
			if act := strings.TrimSpace(a.Action); act == "allow" || act == "ask" || act == "deny" {
				newAction = act
			}
			updated, err := s.m.pg.UpdateInterceptRule(
				target.ID, target.Name, target.MatchTarget, target.MatchType,
				newPattern, newAction, target.Message, target.Priority, *a.Enabled,
				target.TimeoutEnabled, target.TimeoutSeconds, target.TimeoutAction,
			)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if s.m.interceptor != nil {
				s.m.interceptor.Invalidate()
			}
			return jsonResult(updated)
		})
}
