package agent

import (
	"bytes"
	"text/template"
	"time"
)

// PromptOverride, if set, returns the stored system-prompt template for an agent
// key and whether one exists. The server wires it to the PG agent_prompts table.
// When nil or no override exists, agents use their built-in default prompt — so
// behavior is identical until a user edits a prompt in the UI.
var PromptOverride func(agentKey string) (string, bool)

// OpsecEnabled is wired by the server to the persisted global setting. Keeping
// the block here makes it a code-owned runtime tail: database-edited prompts
// cannot accidentally remove the operational safety guidance.
var OpsecEnabled func() bool

const opsecPromptBlock = `[OPSEC & Stealth Guidelines (Hard Constraint — second only to Authorization Scope & Task Constraints)]

- Reuse existing recorded traffic, browser sessions, and verified evidence first; when traffic_search/traffic_get or existing responses already contain the answer, do not issue redundant requests to the target.
- Route all external target interactions through the platform's configured egress/recording proxy (HTTP_PROXY / HTTPS_PROXY / ALL_PROXY are pre-injected in Bash and WebFetch; internal localhost/127.0.0.1 traffic automatically bypasses the proxy via NO_PROXY). Never bypass the configured proxy to hit external targets directly.
- Never expose default CLI/scanner User-Agents (such as bare curl, python-requests, Go-http-client, sqlmap, nuclei) or leak the ARTEX platform's own domain/IP in Referer, Origin, or callback headers. When running curl or custom scripts in Bash, pass a realistic browser User-Agent (-A "Mozilla/5.0 ...") or rely on the platform stealth proxy to cloak headers.
- Do not use -k, --insecure, or verify=False when the platform proxy CA is already trusted in the environment.
- Pace your requests to avoid triggering WAF/Cloudflare rate-limits or IP blocks: do NOT launch high-concurrency floods, tight unthrottled loops, or massive brute-force scans. Prefer targeted, low-noise probes with short delays between requests. If you encounter HTTP 429, CAPTCHA, or WAF blocks, immediately stop the noisy vector, invoke the Skill tool (e.g., "waf-and-filter-bypass" or "redteam-detection-surface-and-resilience"), and pivot to a stealthy approach.
- Use the Skill tool proactively to load specialized offensive playbooks (e.g., "osint-and-surface-mapping", "api-recon", "web-vuln-exploitation", "auth-and-jwt-attacks", "waf-and-filter-bypass") and synchronize discovered assets/findings via insert_assets and report_finding.
- If a tool call is blocked by an ARTEX platform interception rule ([ARTEX Platform Control · Non-Target Defense]), recognize that it is an internal platform safety rule (not a target WAF) and immediately pivot to a safe, non-destructive method.`

// Prompt-variable structs — fields mirror each agent's catalog (docs §5a) so a
// user template referencing a catalog variable renders; referencing anything else
// fails template execution and falls back to the built-in default.
type PlannerVars struct{ Goal, Scope, AssetSummary, DataDir, Now string }
type WorkerVars struct{ ProxyAddr, WorkerName, DataDir, Now string }
type MainVars struct{ Goal, AssetSummary, FindingsSummary, DataDir, Now string }
type GoalsVars struct{ EngagementDescription, DataDir, Now string }

// nowStr is the server-local wall-clock string exposed as the universal {{.Now}}
// prompt variable. renderSystem runs on every agent turn/round, so this is fresh
// each run — a prompt can subtract it from a fixed start stamp to reason about
// elapsed time (e.g. a timed benchmark's "last N hours" window).
func nowStr() string { return time.Now().Format("2006-01-02 15:04:05 MST") }

// renderSystem returns the rendered system-prompt BODY (段 [A]) for agentKey.
// Precedence: the DB-stored template (if any) over the built-in default template
// (def). BOTH are Go templates now — the built-in default is seeded into the DB
// verbatim, so the two paths render identically until a user edits the prompt.
// Rendering always runs (def used to be pre-substituted plain text; it is now a
// {{.Var}} template like the DB one). On any render error we fall back to the
// default template, then to the raw default string — an agent never starts with a
// half-rendered prompt. Callers append the code-owned tail (trafficTool / 中间产物
// 输出规约) AFTER this, so those can't be edited away via the DB body.
func renderSystem(agentKey, def string, vars any) string {
	tmpl := def
	if PromptOverride != nil {
		if t, ok := PromptOverride(agentKey); ok && t != "" {
			tmpl = t
		}
	}
	if out, err := renderTmpl(tmpl, vars); err == nil {
		if OpsecEnabled != nil && OpsecEnabled() {
			return out + "\n\n" + opsecPromptBlock
		}
		return out
	}
	// DB template broke (e.g. references an out-of-catalog var) → code default.
	if out, err := renderTmpl(def, vars); err == nil {
		if OpsecEnabled != nil && OpsecEnabled() {
			return out + "\n\n" + opsecPromptBlock
		}
		return out
	}
	if OpsecEnabled != nil && OpsecEnabled() {
		return def + "\n\n" + opsecPromptBlock
	}
	return def
}

func renderTmpl(tmpl string, vars any) (string, error) {
	t, err := template.New("p").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}
