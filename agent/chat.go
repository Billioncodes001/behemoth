package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// ChatAgent is the generic, task-independent conversational runner behind the chat
// page. It generalizes MainAgent.Chat: any agent (built-in OR a custom one, by
// key) can be chatted with, multi-turn history resumed from the transcript. It is
// a PURE ASSISTANT — base tools are the SDK DefaultTools (Bash/Read/Write/Edit/
// LS/Glob/Grep) plus whatever skills/MCP the key is made visible; NO pentest
// graph/task context is injected (that stays exclusive to MainAgent).
type ChatAgent struct {
	prov            llm.Provider
	model           string
	workDir         string
	tx              *transcript.Store
	window          int
	proxyAddr       string
	proxyAddrFn     func() string
	outboundProxyFn func() bool
	proxyCACert     string
	webSearch       WebSearchOpts
	guard           *guard.Guard // optional; nil disables intercept hooks for chat
	nonStreamingFn  func() bool  // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn    func() bool  // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn     func() int   // resolver: per-reply output cap (nil/0 = send no cap)
}

func NewChatAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window int) *ChatAgent {
	return &ChatAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window}
}

// SetNonStreaming wires a resolver deciding whether chat runs use the
// non-streaming model path (true = non-streaming). nil/unset = streaming.
func (c *ChatAgent) SetNonStreaming(fn func() bool) { c.nonStreamingFn = fn }

func (c *ChatAgent) nonStreaming() bool { return c.nonStreamingFn != nil && c.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether chat runs use the experimental
// noa context-compression mechanism. nil/unset = off (built-in compaction). Read
// per run so the settings toggle takes effect without rebuilding the agent.
func (c *ChatAgent) SetNoaEnabled(fn func() bool) { c.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (c *ChatAgent) SetMaxTokens(fn func() int) { c.maxTokensFn = fn }

func (c *ChatAgent) maxTokens() int {
	if c.maxTokensFn == nil {
		return 0
	}
	return c.maxTokensFn()
}

// SetProxy points the chat agent's WebFetch/Bash at the recording proxy plus the
// CA cert it trusts (empty addr = direct). Kept for parity with the other agents.
func (c *ChatAgent) SetProxy(addr, caCert string)         { c.proxyAddr, c.proxyCACert = addr, caCert }
func (c *ChatAgent) SetProxyProvider(fn func() string)    { c.proxyAddrFn = fn }
func (c *ChatAgent) SetOutboundProxyCheck(fn func() bool) { c.outboundProxyFn = fn }

// SetWebSearch selects the web_search backend for the chat agent (off by default).
func (c *ChatAgent) SetWebSearch(o WebSearchOpts) { c.webSearch = o }

// SetGuard attaches a guard (with user-configured intercept rules) to this chat
// agent. Must be called before Chat; safe to call multiple times.
func (c *ChatAgent) SetGuard(g *guard.Guard) { c.guard = g }

// chatWorkDirSpec returns a working-directory notice appended to every chat
// agent's system prompt, plus the active runtime model identity so the model
// never hallucinates or guesses a different model name from its training data.
func chatWorkDirSpec(workDir, model string) string {
	out := "\n\n**File Output Specification**: When writing files, always write to the session working directory " + workDir + " (this is the default CWD; relative paths resolve here, or you may use this absolute path) — do not write to /tmp or other external paths."
	if model != "" {
		out += "\n\n**Runtime Model Identity & Language Policy**: You are currently powered by and running on the LLM model `" + model + "`. If the user asks which LLM or model you are currently using, always state `" + model + "` accurately. Always respond strictly in **English** (never output Chinese, even when summarizing or using a bilingual model)."
	}
	return out
}

// chatSystem renders the DB-managed prompt body for agentKey. Custom agents have
// no per-key in-code default, so DefaultAssistantPrompt is the render fallback.
func chatSystem(agentKey, model, dataDir, workDir string) string {
	return renderSystem(agentKey, DefaultAssistantPrompt, chatVars{DataDir: dataDir, Now: nowStr()}) + chatWorkDirSpec(workDir, model) + needReportNote
}

// chatVars carries the runtime variables a custom agent's prompt may reference.
// DataDir (server data root) + Now (server wall-clock, refreshed each turn) are the
// universal ones; any other {{.X}} fails to render and falls back to
// DefaultAssistantPrompt.
type chatVars struct{ DataDir, Now string }

// Chat runs ONE turn of a conversation with the agent identified by agentKey,
// resuming prior history keyed by sessionID. maxTurns is the per-turn agent step
// budget (0 = unlimited). maxDuration is the wall-clock run budget per turn
// (0 = unlimited); the timer resets each time Chat is called, so a new user
// message always starts a fresh countdown. webSearch gates network search for
// THIS agent (the global backend/key still come from the chat agent's config,
// but each agent decides on/off). emit receives each execution step (thinking /
// tool_use / tool_result / text / result), tagged with the agent key as the
// worker lane.
func (c *ChatAgent) Chat(ctx context.Context, agentKey, sessionID, message string, maxTurns int, maxDuration time.Duration, webSearch bool, emit func(db.Activity)) (string, error) {
	// gate the global web-search opts by this agent's own flag.
	ws := c.webSearch
	if !webSearch {
		ws.Enabled = false
	}

	// Per-session working directory: <workDir>/sessions/<sessionID>/
	// Isolates file writes across conversations, mirroring how workers use i<intentID>/.
	sessionWorkDir := filepath.Join(c.workDir, "sessions", sessionID)
	_ = os.MkdirAll(sessionWorkDir, 0o755)
	ctx = intercept.WithReviewWorkingDirectory(ctx, sessionWorkDir)

	// Pure assistant: DefaultTools as the base; AugmentTools layers in the key's
	// visible skills/MCP and lets the DB tools table filter/override. DefaultTools
	// have no tools-table rows, so they always pass through.
	base := actool.DefaultTools()
	ctx = WithRunInfo(ctx, RunInfo{SessionID: sessionID})
	tools, def, cleanup := AugmentTools(ctx, agentKey, base)
	defer cleanup()

	system, boundary := deferredSystem(chatSystem(agentKey, c.model, c.workDir, sessionWorkDir), def)

	resolveLiveProxy := func() string {
		// proxy_harvester discovers & verifies public proxy feeds to replenish an empty or
		// exhausted Proxy Pool; it must never be deadlocked by the fail-closed target guard.
		if strings.EqualFold(strings.TrimSpace(agentKey), "proxy_harvester") {
			return ""
		}
		// When an external outbound proxy (Proxy Pool or Global Proxy) is enabled, EVERY
		// agent role routes through the proxy so the server's real IP is NEVER exposed.
		// Only when NO outbound proxy is enabled do non-probing roles skip local 127.0.0.1:8788 capture.
		hasOutbound := c.outboundProxyFn != nil && c.outboundProxyFn()
		if !hasOutbound && !isActiveProbingAgent(agentKey) {
			return ""
		}
		if c.proxyAddrFn != nil {
			return c.proxyAddrFn()
		}
		return c.proxyAddr
	}
	proxyAddr := resolveLiveProxy()
	allTools := wrapDynamicProxyEnvTools(append(tools, deepSeekTools(ws)...), resolveLiveProxy, c.proxyCACert)
	boundToolMap := make(map[string]bool, len(allTools))
	for _, t := range allTools {
		boundToolMap[t.Name()] = true
	}

	opts := agentcore.Options{
		Provider:           c.prov,
		SystemPrompt:       system,
		DynamicBoundary:    boundary,
		Tools:              allTools,
		DeferredTools:      def.Deferred,
		UnlockSet:          def.Unlock,
		PermissionMode:     permission.ModeBypass,
		EnableWebFetch:     true,
		WebFetchProxy:      proxyAddr,
		WebFetchCACert:     c.proxyCACert,
		EnableWebSearch:    ws.Enabled && ws.Backend != "deepseek",
		WebSearchBackend:   ws.Backend,
		BraveSearchAPIKey:  ws.BraveKey,
		TavilySearchAPIKey: ws.TavilyKey,
		WebSearchProxy:     ws.Proxy,
		BashEnv:            agentBashEnv(proxyAddr, c.proxyCACert),
		WorkingDir:         sessionWorkDir,
		MaxTurns:           maxTurns,
		MaxDuration:        maxDuration,
		Compaction:         compactionConfig(c.window),
		Todos:              actool.NewTodoStore(),
		ToolOutputDir:      filepath.Join(sessionWorkDir, "cmd-output"),
		Settlement:         wrapupSettlement(agentKey, nil),
		NonStreaming:       c.nonStreaming(),
		MaxTokens:          c.maxTokens(),
	}
	if c.guard != nil {
		opts.Hooks = c.guard.Hooks()
	}
	opts.Hooks = WrapChatContinuationHooks(opts.Hooks, agentKey, boundToolMap, message, agentKey+"-"+sessionID, 8)
	if c.tx != nil { // persist raw human↔AI conversation; one accumulating file per thread
		opts.Transcript = c.tx
		opts.SessionID = sessionID
	}
	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	enableNoa(&opts, c.noaEnabledFn, c.workDir, "chat-"+sessionID, noaWarn("chat-"+sessionID))
	ctx = attachSideCapture(ctx, &opts)
	s := newAgentSession(opts)
	defer s.Close()
	// reload prior conversation so the agent has context across turns (each Chat is
	// a fresh session). First turn: no file yet → Resume loads nothing and proceeds.
	if c.tx != nil {
		_ = s.Resume(sessionID)
	}
	// re-unlock skill-gated MCPs from prior Skill() calls in the reloaded history so
	// revealed tools stay callable across the fresh session.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = agentKey
			emit(r)
		}
	})
	return text, err
}

// dynamicProxyEnvTool refreshes tc.Env right before each tool call so mid-turn proxy
// changes (e.g. calling import_and_test_proxies or manage_proxy_pool(disable) inside
// the same Chat turn) immediately inject or strip HTTP_PROXY/HTTPS_PROXY/ALL_PROXY.
type dynamicProxyEnvTool struct {
	actool.CoreTool
	resolveProxy func() string
	caCert       string
}

func (d *dynamicProxyEnvTool) AcceptsRawInput() bool {
	if ra, ok := d.CoreTool.(rawInputAcceptor); ok {
		return ra.AcceptsRawInput()
	}
	return false
}

func (d *dynamicProxyEnvTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if tc != nil && d.resolveProxy != nil {
		liveAddr := d.resolveProxy()
		cleaned := make([]string, 0, len(tc.Env)+12)
		for _, kv := range tc.Env {
			k := kv
			if eq := strings.IndexByte(kv, '='); eq >= 0 {
				k = kv[:eq]
			}
			switch strings.ToUpper(k) {
			case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY",
				"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS":
				continue
			}
			cleaned = append(cleaned, kv)
		}
		cleaned = append(cleaned, proxyEnv(liveAddr, d.caCert)...)
		tcCopy := *tc
		tcCopy.Env = cleaned
		tc = &tcCopy
	}
	return d.CoreTool.Call(ctx, in, tc)
}

func wrapDynamicProxyEnvTools(tools []actool.CoreTool, resolveProxy func() string, caCert string) []actool.CoreTool {
	if resolveProxy == nil {
		return tools
	}
	out := make([]actool.CoreTool, len(tools))
	for i, t := range tools {
		out[i] = &dynamicProxyEnvTool{CoreTool: t, resolveProxy: resolveProxy, caCert: caCert}
	}
	return out
}
