package server

import (
	"context"
	"encoding/json"
	"log"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
)

// maxLedgerSkillName caps the skill name stored for a MISS — that string comes
// straight from the model and is otherwise unbounded.
const maxLedgerSkillName = 128

// meteredSkill wraps the Skill meta-tool to append one skill_usage row per call.
// The metering lives here rather than in Registry.OnInvoke because OnInvoke only
// receives the resolved Skill: it never fires for an unknown skill name (norma
// returns a tool error before the hook) and it cannot see the caller's args. Both
// matter — a miss tells you which procedure the agents wished existed.
type meteredSkill struct {
	actool.CoreTool
	pg       *db.DB
	reg      *skill.Registry
	agentKey string
	ri       agent.RunInfo
}

// meterSkillTool returns t unchanged when there is no DB to meter into.
func meterSkillTool(t actool.CoreTool, pg *db.DB, reg *skill.Registry, agentKey string, ri agent.RunInfo) actool.CoreTool {
	if pg == nil {
		return t
	}
	return &meteredSkill{CoreTool: t, pg: pg, reg: reg, agentKey: agentKey, ri: ri}
}

var builtinSkillAliases = map[string]string{
	"waf":                        "waf-and-filter-bypass",
	"waf-bypass":                 "waf-and-filter-bypass",
	"filter-bypass":              "waf-and-filter-bypass",
	"cloudflare-bypass":          "waf-and-filter-bypass",
	"sqli":                       "web-vuln-exploitation",
	"sql-injection":              "web-vuln-exploitation",
	"sqli-deepdive":              "web-vuln-exploitation",
	"xss":                        "web-vuln-exploitation",
	"xss-client-audit":           "web-vuln-exploitation",
	"ssrf":                       "web-vuln-exploitation",
	"ssrf-cloud-probe":           "web-vuln-exploitation",
	"rce":                        "web-vuln-exploitation",
	"lfi":                        "web-vuln-exploitation",
	"ssti":                       "web-vuln-exploitation",
	"idor":                       "web-vuln-exploitation",
	"idor-bola-matrix":           "web-vuln-exploitation",
	"web-exploitation":           "web-vuln-exploitation",
	"jwt":                        "auth-and-jwt-attacks",
	"jwt-auth-bypass":            "auth-and-jwt-attacks",
	"auth":                       "auth-and-jwt-attacks",
	"auth-bypass":                "auth-and-jwt-attacks",
	"authentication":             "auth-and-jwt-attacks",
	"oauth":                      "auth-and-jwt-attacks",
	"captcha":                    "captcha-solving",
	"2captcha":                   "captcha-solving",
	"turnstile":                  "captcha-solving",
	"recaptcha":                  "captcha-solving",
	"honeypot":                   "deception-and-honeypot-detection",
	"deception":                  "deception-and-honeypot-detection",
	"honeypot-detection":         "deception-and-honeypot-detection",
	"osint":                      "osint-and-surface-mapping",
	"recon":                      "osint-and-surface-mapping",
	"reconnaissance":             "osint-and-surface-mapping",
	"subdomain-enumeration":      "osint-and-surface-mapping",
	"surface-mapping":            "osint-and-surface-mapping",
	"api":                        "api-recon",
	"api-security":               "api-recon",
	"graphql":                    "api-recon",
	"cloud":                      "cloud-and-container-audit",
	"cloud-audit":                "cloud-and-container-audit",
	"container-audit":            "cloud-and-container-audit",
	"docker-audit":               "cloud-and-container-audit",
	"network-pentest":            "network-and-service-pentest",
	"service-pentest":            "network-and-service-pentest",
	"privesc":                    "privilege-escalation",
	"linux-privesc":              "privilege-escalation",
	"windows-privesc":            "privilege-escalation",
	"playwright":                 "playwright-cli",
	"browser":                    "playwright-cli",
	"browser-automation":         "playwright-cli",
	"proxy":                      "proxy-harvesting",
	"proxy-scraper":              "proxy-harvesting",
}

func normalizeRequestedSkillName(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "skills/")
	s = strings.TrimSuffix(s, "/SKILL.md")
	s = strings.TrimSuffix(s, ".md")
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.Join(strings.Fields(s), "-")
	if mapped, ok := builtinSkillAliases[s]; ok {
		return mapped
	}
	return s
}

func (m *meteredSkill) resolveInput(input json.RawMessage) json.RawMessage {
	if m.reg == nil {
		return input
	}
	var rawMap map[string]any
	if err := json.Unmarshal(input, &rawMap); err != nil {
		return input
	}
	name, _ := rawMap["name"].(string)
	if strings.TrimSpace(name) == "" {
		return input
	}
	if _, ok := m.reg.Get(strings.TrimSpace(name)); ok {
		return input
	}
	norm := normalizeRequestedSkillName(name)
	if norm != "" {
		if sk, ok := m.reg.Get(norm); ok {
			rawMap["name"] = sk.Name
			if rewritten, err := json.Marshal(rawMap); err == nil {
				return rewritten
			}
		}
		// Match by directory basename in case skill frontmatter Name differs from folder name.
		for _, sk := range m.reg.List() {
			base := strings.ToLower(filepath.Base(sk.Dir))
			if base == norm || strings.ToLower(sk.Name) == norm {
				rawMap["name"] = sk.Name
				if rewritten, err := json.Marshal(rawMap); err == nil {
					return rewritten
				}
			}
		}
	}
	return input
}

func (m *meteredSkill) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	cleanIn := agent.SanitizeToolInput(m.Name(), input, m.InputSchema())
	cleanIn = m.resolveInput(cleanIn)
	m.record(cleanIn)
	return m.CoreTool.Call(ctx, cleanIn, tc)
}

// record appends the ledger row. Best-effort by design: a metering failure must
// never turn into a failed skill invocation, so every error path just logs.
func (m *meteredSkill) record(input json.RawMessage) {
	var in struct {
		Name string `json:"name"`
		Args string `json:"args"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return // malformed call; norma will reject it too
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return
	}
	// Resolve to the directory name so the ledger keys match agent_skill_visibility
	// and the skills page (a skill's display Name can differ from its directory).
	found := false
	if m.reg != nil {
		if s, ok := m.reg.Get(name); ok {
			found = true
			if s.Dir != "" {
				name = filepath.Base(s.Dir)
			}
		}
	}
	if len(name) > maxLedgerSkillName {
		name = name[:maxLedgerSkillName]
	}
	err := m.pg.InsertSkillUsage(&db.SkillUsage{
		Skill:         name,
		AgentKey:      m.agentKey,
		TaskID:        m.ri.TaskID,
		ExplorationID: m.ri.ExplorationID,
		IntentID:      m.ri.IntentID,
		SessionID:     m.ri.SessionID,
		ArgsLen:       len(in.Args),
		Found:         found,
	})
	if err != nil {
		log.Printf("[skillusage] insert: %v", err)
	}
}
