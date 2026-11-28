package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/c2"
	"github.com/Autumn-27/behemoth/db"
	"github.com/Autumn-27/behemoth/intercept"
	"github.com/Autumn-27/behemoth/intercept/jev"
	"github.com/Autumn-27/behemoth/llmpool"
	"github.com/Autumn-27/behemoth/llmrec"
	"github.com/Autumn-27/behemoth/phish"
	"github.com/Autumn-27/behemoth/report"
	"github.com/Autumn-27/behemoth/server/browser"
	"github.com/Autumn-27/behemoth/server/factgraph"
	"github.com/Autumn-27/behemoth/server/fingerprint"
	"github.com/Autumn-27/behemoth/server/patchmonitor"
	"github.com/Autumn-27/behemoth/server/proxy/v2"
	"github.com/Autumn-27/behemoth/server/recipes"
	"github.com/Autumn-27/behemoth/server/search"
	"github.com/Autumn-27/behemoth/server/security"
	"github.com/Autumn-27/behemoth/server/targets"
	"github.com/Autumn-27/behemoth/server/tools"
	"github.com/Autumn-27/behemoth/traffic"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// BuildVersion is the backend application version, injected from cmd/behemoth at
// startup (which in turn gets it from -ldflags "-X main.version=<tag>").
// Defaults to "dev" for local builds. Exposed via the authenticated GET /api/version.
var BuildVersion = "dev"

// Server exposes the BEHEMOTH backend over a JSON HTTP API for the shadcn/ui
// frontend.
type Server struct {
	scheduleMu sync.Mutex
	m          *Manager
	engine     *Engine
	ctx        context.Context
	cancel     context.CancelFunc
	dataDir    string
	metricsMu  sync.Mutex
	lastCPUUse uint64
	lastCPUAt  time.Time

	skillDir  string // root directory for skill subdirectories
	jwtKey    []byte // HS256 signing key loaded from / generated into dataDir/jwt.key
	basicAuth basicAuthGate
	// loginGuard throttles repeated wrong credentials on /api/auth/*, which
	// securityMiddleware's generic limiter never sees (it exempts that prefix).
	loginGuard loginGuard

	// mcpStoreOverride replaces the PostgreSQL-backed MCP server store in tests.
	mcpStoreOverride mcpStore
	// mcpCreateMu serializes MCP task creation so a token's quota check and the
	// creation it guards cannot interleave with another request on the same token.
	mcpCreateMu sync.Mutex

	// concMu serializes concurrency-cap decisions (admission + reconcile) so a
	// scheduler tick and an HTTP settings change / task creation can't both count
	// free slots off the same snapshot and over-promote past the limit.
	concMu sync.Mutex

	cfgMu     sync.Mutex
	chatAgent *agent.ChatAgent // conversational runner for the chat page; nil w/o LLM
	// llmProv is the fully-decorated global provider (recorder + failover chain)
	// installed by applyLLM. Task routers use it after an explicit chain is cleared.
	llmProv   llm.Provider
	llmDirect llm.Provider // concrete global provider, before any failover pool
	llmCfg    agent.Config // current LLM config (key not exposed)
	llmOn     bool
	llmProf   string // active LLM profile name (for llmrec tagging)

	// chatBusy guards the per-task main-agent run: the chat handler launches the
	// agent on the server's background ctx (not the request ctx) and returns
	// immediately, so a page reload / proxy timeout can't abort a live run. This
	// map serializes turns per task — one main-agent run at a time per task, so
	// concurrent messages don't corrupt the shared exp<id>-main transcript.
	chatMu   sync.Mutex
	chatBusy map[string]bool
	// chatCancel holds the cancel func for each in-flight conversation run (keyed by
	// convBusyKey), so a manual stop can abort JUST that session's agent run. Set/
	// cleared alongside chatBusy under chatMu. Aborting a run does NOT touch the P3
	// trigger queue — the drain goroutine simply proceeds to the next queued fire.
	chatCancel map[string]context.CancelCauseFunc

	inFlightMu               sync.Mutex
	activeTurns              map[string]persistedInFlightTurn
	liveUpdateTurnsPersisted bool

	// triggerQ buffers P3 trigger fires PER AGENT. A per-agent "pump" launches runs up
	// to a concurrency limit derived from the agent's strategy: serial -> limit 1 (+ optional
	// merge); parallel -> limit = trigger_max_parallel (0=inf), no merge. triggerActive
	// counts in-flight runs per agent (replaces a boolean drain flag); a run's
	// completion decrements it and re-pumps to fill the freed slot. triggerCfg caches
	// the agent's last-read strategy so the pump never queries the DB while holding queueMu.
	// Distinct agents always run concurrently. Queue is in-memory (matches chatBusy); a
	// restart drops pending fires -- the scheduler re-fires from watermarks next tick.
	queueMu       sync.Mutex
	triggerQ      map[string][]triggeredRun
	triggerActive map[string]int
	triggerCfg    map[string]triggerBehavior

	// profChatAgents caches a per-profile ChatAgent (chat page), keyed by profile id.
	// Built lazily on first use; invalidated when any profile is saved/activated/deleted
	// so edits take effect.
	profMu         sync.Mutex
	profChatAgents map[int64]*agent.ChatAgent // per-profile ChatAgent cache (chat page)

	// provByProfile caches ONE provider per LLM profile id so every agent bound or
	// pinned to the same profile shares a single provider instance — hence one rate
	// limiter. applyLLM also resolves the persisted global-active profile through this
	// cache, so global fallback and task chains do not accidentally double the
	// configured request rate. Cleared on profile edits, then repopulated by active reapply.
	provCacheMu   sync.Mutex
	provByProfile map[int64]*provEntry
	provCacheGen  uint64
	// Quota histories survive provider/agent cache invalidation. Key 0 belongs
	// to the non-persisted global config; persisted profiles use their DB IDs.
	requestLimiters map[int64]*agent.RequestLimiter

	// llmHealth is the process-wide circuit-breaker state for LLM failover (轮询).
	// It deliberately lives OUTSIDE the provider caches: rebuilding the chain
	// (saving an unrelated profile, flipping a setting) must not erase what we
	// learned about which backends are out of credit / rate-limited.
	llmHealth *llmpool.Registry

	// Explicit task chains use one task-scoped dynamic provider shared by goals,
	// planner, workers, and the main agent. Bundles are stable; their runtime reads
	// the persisted current profile at every new LLM call.
	taskAgentMu sync.Mutex
	taskAgents  map[string]*taskAgentBundle

	// Cold task archives run through one persistent FIFO worker. The buffered wake
	// channel coalesces enqueue bursts; the database remains the source of truth.
	archiveWake       chan struct{}
	archiveWG         sync.WaitGroup
	credentialWake    chan struct{}
	proxyReconnect    proxyReconnectSupervisor
	proxyPoolWake     chan struct{}
	proxyPoolWG       sync.WaitGroup
	proxyPoolProbeSem chan struct{}
	proxyPoolTickMu   sync.Mutex
	// proxyProbe is injectable for deterministic reconnect race tests. Production
	// servers leave it nil and use probeEgress directly.
	proxyProbe func(context.Context, string, string, []string, time.Duration) egressProbeResult
	side       *sideQuestionState

	// Recipe registry for tool definitions (CyberStrikeAI-style)
	recipeReg *recipes.RecipeRegistry

	// Fact graph for intelligence gathering (sapper-v2 style)
	factGraph *factgraph.Graph

	// Tool catalog and executor (HexStrike-inspired)
	toolCatalog  *tools.Catalog
	toolExecutor *tools.ToolExecutor

	// Target connectors for remote execution
	// C2 (self-contained command & control): lazily initialized manager,
	// implant-facing HTTP handlers, operator console, optional listener.
	c2Mu      sync.Mutex
	c2mgr     *c2.Manager
	c2Handler *c2.Handler
	c2Console *c2.Console
	c2srv     *http.Server

	// AiTM phishing (DOMDIFFER-style): lazily initialized manager + dedicated
	// listener serving all phish sites (Host-multiplexed).
	phishMu  sync.Mutex
	phishM   *phish.Manager
	phishSrv *http.Server
	phishLn  net.Listener

	targetMu sync.Mutex
	targets  map[string]targets.TargetConnector // keyed by target ID

	// Security modules (anti-bot/IOC/backdoor detection)
	iocBlocklist     *security.IOCBlocklist
	antiDetect       *security.AntiDetect
	backdoorDetector *security.BackdoorDetector

	// Multi-engine web search (Pentagi-inspired)
	searchOrchestrator *search.Orchestrator

	// Browser automation (Pentagi-inspired)
	browserScraper *browser.Scraper

	// Patch Monitor for security vulnerability tracking and auto-exploit generation
	patchMon *patchmonitor.Monitor
}

// provEntry is a cached provider + its config for one LLM profile id.
type provEntry struct {
	prov llm.Provider
	cfg  agent.Config
	// jev is retained in the cache entry so a cached chat provider can be
	// returned without consulting the DB on every hot-path resolution.
	jev bool
}

// triggeredRun is one queued P3 trigger fire awaiting its turn for an agent.
// taskID + mergeable let the drainer coalesce several event triggers (finding/goal)
// from the SAME task into one conversation before it starts (interval fires don't merge).
type triggeredRun struct {
	conversationID int64 // pre-created manual finding review; never coalesced

	agentKey  string
	title     string
	message   string // Event body (trigger phrase + tool/input/output); excludes task desc/goal header
	taskID    int64  // source task for finding/goal triggers; 0 for interval/none
	taskDesc  string // Task description (task-level, same for all runs in task); rendered once on merge
	taskGoal  string // Task goal (task-level, same for all runs in task); rendered once on merge
	mergeable bool   // true for finding/goal event triggers (merge by taskID)
}

func New(ctx context.Context, m *Manager, skillDir string, dataDir string, keyDir string) *Server {
	key, err := loadOrCreateJWTKey(keyDir, dataDir)
	if err != nil {
		log.Fatalf("[auth] JWT key: %v", err)
	}
	srvCtx, srvCancel := context.WithCancel(ctx)
	s := &Server{m: m, engine: NewEngine(m), ctx: srvCtx, cancel: srvCancel, skillDir: skillDir, dataDir: dataDir, jwtKey: key, chatBusy: map[string]bool{},
		chatCancel: map[string]context.CancelCauseFunc{}, triggerQ: map[string][]triggeredRun{},
		triggerActive: map[string]int{}, triggerCfg: map[string]triggerBehavior{}, proxyPoolWake: make(chan struct{}, 1), proxyPoolProbeSem: make(chan struct{}, proxyPoolMaxProbeConcurrency),
		profChatAgents: map[int64]*agent.ChatAgent{},
		provByProfile:  map[int64]*provEntry{}, llmHealth: newLLMHealthRegistry(m.pg),
		taskAgents: map[string]*taskAgentBundle{}, archiveWake: make(chan struct{}, 1), credentialWake: make(chan struct{}, 1)}
	m.SetTaskControlMutex(&s.concMu)
	m.RegisterOnClose(s.Close)

	// Initialize dynamic fingerprint system (randomizes cookies, headers, UAs per startup)
	fingerprint.Initialize()
	InitializeDynamicNames()

	// Start runtime fingerprint rotation scheduler (rotate UAs every 5 minutes)
	// This ensures fingerprints change DURING runtime, not just on restart
	_ = fingerprint.StartRotationScheduler(5 * time.Minute)

	// Initialize Proxy Pool v2 system (if DB available)
	if m.pg != nil {
		s.initProxyPoolV2(m)
	}
	s.startGitAutoSync(s.ctx)

	// Initialize Recipe Registry (tool definitions)
	s.recipeReg = recipes.NewRecipeRegistry(filepath.Join(dataDir, "recipes", "tools"))
	if err := s.recipeReg.Load(); err != nil {
		log.Printf("[recipes] Warning: could not load recipes: %v", err)
	} else {
		log.Printf("[recipes] Loaded %d tool recipes", s.recipeReg.Count())
	}

	// Initialize Fact Graph (intelligence gathering)
	s.factGraph = factgraph.NewGraph()
	log.Printf("[factgraph] Fact graph initialized")

	// Initialize Tool Catalog & Executor (HexStrike-inspired)
	s.toolCatalog = tools.NewCatalog()
	s.toolExecutor = tools.NewToolExecutor(s.toolCatalog, tools.DefaultExecutorConfig())
	s.toolExecutor.SetProxyProvider(s.m.OutboundProxyAddr)
	s.toolExecutor.SetEnvProvider(func() []string {
		px := s.m.OutboundProxyAddr()
		if px == "" && s.m.TrafficEnabled() {
			px = s.m.SessionProxyAddr()
		}
		if px == "" {
			return nil
		}
		return []string{
			"HTTP_PROXY=" + px, "HTTPS_PROXY=" + px, "ALL_PROXY=" + px,
			"http_proxy=" + px, "https_proxy=" + px, "all_proxy=" + px,
			"NO_PROXY=127.0.0.1,localhost,::1", "no_proxy=127.0.0.1,localhost,::1",
		}
	})
	s.targets = make(map[string]targets.TargetConnector)
	s.ensureDefaultWordlists()
	log.Printf("[tools] Tool catalog loaded: %d tools", s.toolCatalog.Count())

	// Initialize Security Modules (IOC blocking, anti-detect, backdoor detection)
	s.iocBlocklist = security.NewIOCBlocklist()
	stealthCfg := security.DefaultStealthConfig()
	if m.pg != nil {
		if raw, ok, _ := m.pg.GetSetting("security_stealth_config"); ok && strings.TrimSpace(raw) != "" {
			_ = json.Unmarshal([]byte(raw), &stealthCfg)
		}
		if rawIOCs, ok, _ := m.pg.GetSetting("security_ioc_blocked_ips"); ok && strings.TrimSpace(rawIOCs) != "" {
			var ips []string
			if json.Unmarshal([]byte(rawIOCs), &ips) == nil && len(ips) > 0 {
				s.iocBlocklist.SetBlockedIPs(ips)
			}
		}
	}
	s.antiDetect = security.NewAntiDetect(stealthCfg)
	s.backdoorDetector = security.NewBackdoorDetector()
	if m.traffic != nil {
		m.traffic.SetOutboundModifier(func(host string, hdr http.Header) {
			if s.antiDetect != nil {
				s.antiDetect.ApplyOutboundStealth(host, hdr)
			}
		})
	}
	if m.forwardProxy != nil {
		m.forwardProxy.outboundMod = func(host string, hdr http.Header) {
			if s.antiDetect != nil {
				s.antiDetect.ApplyOutboundStealth(host, hdr)
			}
		}
	}
	log.Printf("[security] Security modules initialized: IOC blocklist (%d IPs), anti-detect (enabled=%v), backdoor detector", len(s.iocBlocklist.GetStats().BlockedIPs), stealthCfg.Enabled)

	// Initialize Multi-Engine Web Search (Pentagi-inspired)
	searchCfg := search.DefaultConfig()
	// Load search config from environment first, then DB settings override
	if apiKey := os.Getenv("SEARCH_FIRECRAWL_API_KEY"); apiKey != "" {
		searchCfg.Firecrawl.APIKey = apiKey
	}
	if firecrawlURL := os.Getenv("SEARCH_FIRECRAWL_URL"); firecrawlURL != "" {
		searchCfg.Firecrawl.BaseURL = firecrawlURL
	}
	if apiKey := os.Getenv("SEARCH_TAVILY_API_KEY"); apiKey != "" {
		searchCfg.Tavily.APIKey = apiKey
	}
	if searxngURL := os.Getenv("SEARCH_SEARXNG_URL"); searxngURL != "" {
		searchCfg.SearXNG.URL = searxngURL
	}
	if apiKey := os.Getenv("SEARCH_BRAVE_API_KEY"); apiKey != "" {
		searchCfg.Brave.APIKey = apiKey
	}
	if m.pg != nil {
		if v, ok, _ := m.pg.GetSetting("search_firecrawl_api_key"); ok && strings.TrimSpace(v) != "" {
			if parts := strings.SplitN(strings.TrimSpace(v), "|", 2); len(parts) == 2 {
				searchCfg.Firecrawl.APIKey = strings.TrimSpace(parts[0])
				searchCfg.Firecrawl.BaseURL = strings.TrimSpace(parts[1])
			} else if strings.HasPrefix(strings.TrimSpace(v), "http") {
				searchCfg.Firecrawl.BaseURL = strings.TrimSpace(v)
			} else {
				searchCfg.Firecrawl.APIKey = strings.TrimSpace(v)
			}
		}
		if v, ok, _ := m.pg.GetSetting("search_firecrawl_base_url"); ok && strings.TrimSpace(v) != "" {
			searchCfg.Firecrawl.BaseURL = strings.TrimSpace(v)
		}
		if v, ok, _ := m.pg.GetSetting("search_tavily_api_key"); ok && strings.TrimSpace(v) != "" {
			searchCfg.Tavily.APIKey = strings.TrimSpace(v)
		} else if v, ok, _ := m.pg.GetSetting("tavily_search_api_key"); ok && strings.TrimSpace(v) != "" {
			searchCfg.Tavily.APIKey = strings.TrimSpace(v)
		}
		if v, ok, _ := m.pg.GetSetting("search_searxng_url"); ok && strings.TrimSpace(v) != "" {
			searchCfg.SearXNG.URL = strings.TrimSpace(v)
		}
		if v, ok, _ := m.pg.GetSetting("search_brave_api_key"); ok && strings.TrimSpace(v) != "" {
			searchCfg.Brave.APIKey = strings.TrimSpace(v)
		} else if v, ok, _ := m.pg.GetSetting(settingBraveKey); ok && strings.TrimSpace(v) != "" {
			// Fall back to the Brave key stored for the webfetch search backend.
			searchCfg.Brave.APIKey = strings.TrimSpace(v)
		}
	}
	searchCfg.Firecrawl.Enabled = searchCfg.Firecrawl.APIKey != "" || searchCfg.Firecrawl.BaseURL != ""
	searchCfg.Tavily.Enabled = searchCfg.Tavily.APIKey != ""
	searchCfg.SearXNG.Enabled = searchCfg.SearXNG.URL != ""
	searchCfg.Brave.Enabled = searchCfg.Brave.APIKey != ""
	// Auto-pick up the self-hosted SearXNG instance provisioned by setup.sh on
	// this host (Docker container bound to 127.0.0.1:8888) so agents get free
	// meta-search with zero manual configuration.
	if !searchCfg.SearXNG.Enabled {
		if localURL := search.DetectLocalSearXNG(); localURL != "" {
			searchCfg.SearXNG.URL = localURL
			searchCfg.SearXNG.Enabled = true
			log.Printf("[search] Local SearXNG instance detected at %s — self-hosted meta-search enabled", localURL)
		}
	}
	s.searchOrchestrator = search.NewOrchestrator(searchCfg)
	search.SetProxyProvider(s.m.ActiveOutboundProxyAddr)
	s.startLocalSearXNGSupervisor(s.ctx)
	s.startBountyScannerLoop(s.ctx)
	log.Printf("[search] Search orchestrator initialized with %d engines", len(s.searchOrchestrator.GetAvailableEngines()))

	// Initialize Browser Automation (Pentagi-inspired)
	browserCfg := browser.DefaultConfig()
	browserCfg.ScreenshotDir = filepath.Join(dataDir, "screenshots")
	if envLocal := os.Getenv("BROWSER_USE_LOCAL_CHROME"); envLocal != "" {
		browserCfg.UseLocalChrome = envLocal == "true" || envLocal == "1"
	} else {
		browserCfg.UseLocalChrome = true
	}
	if scraperURL := os.Getenv("BROWSER_SCRAPER_URL"); scraperURL != "" {
		browserCfg.ScraperURL = scraperURL
	}
	if m.pg != nil {
		if v, ok, _ := m.pg.GetSetting("browser_scraper_url"); ok {
			browserCfg.ScraperURL = strings.TrimSpace(v)
		}
		if v, ok, _ := m.pg.GetSetting("browser_use_local_chrome"); ok && strings.TrimSpace(v) != "" {
			browserCfg.UseLocalChrome = strings.TrimSpace(v) == "true" || strings.TrimSpace(v) == "1"
		}
	}
	browserCfg.ProxyProvider = func() string {
		if s.m.HasOutboundProxy() {
			return s.m.OutboundProxyAddr()
		}
		if s.m.TrafficEnabled() {
			return s.m.SessionProxyAddr()
		}
		return ""
	}
	s.browserScraper = browser.NewScraper(browserCfg)
	log.Printf("[browser] Browser automation initialized (local: %v, scraper: %v)",
		browserCfg.UseLocalChrome, browserCfg.ScraperURL != "")

	// Initialize Patch Monitor for security vulnerability tracking
	if m.pg != nil {
		s.patchMon = patchmonitor.NewMonitor(m.pg.DB)
		s.patchMon.SetAgentWatchCallback(s.launchPatchWatchAgentRun)
		s.patchMon.SetProxyProvider(s.m.OutboundProxyAddr)
		s.patchMon.SetNucleiTemplatesDir(filepath.Join(dataDir, "nuclei-templates", "behemoth"))
		log.Printf("[patchmon] Patch monitor initialized")
	}

	s.initSideQuestions()
	if m.pg != nil {
		if err := s.basicAuth.load(m.pg); err != nil {
			log.Fatalf("[auth] load HTTP Basic Auth: %v", err)
		}
	}
	// Circuit-breaker thresholds/cooldown are hot parameters on the failure path.
	// Push global retry policy to Registry once at startup; re-push on each policy save (saveLLMRetryPolicy).
	s.applyRetryPolicy()
	// Every task uses a stable task router. An empty explicit chain is resolved by
	// that router through Agent bindings and then the global provider, so adding a
	// first chain to a running task takes effect on its very next LLM call.
	s.engine.SetAuthoritativeAgentResolver(func(t *Task) (*agent.Planner, *agent.Worker) {
		if !s.taskRuntimeAvailable(t, "planner", "worker") {
			return nil, nil
		}
		b := s.agentsForTask(t)
		return b.pl, b.wk
	})
	s.engine.SetWorkerResolver(func(t *Task, slot WorkerSlot) (*agent.Worker, error) {
		return s.workerForTaskSlot(t, slot)
	})
	// Global readiness (Ready()/llm_configured): a global active LLM provider is
	// installed. Task-level runnability is separate (ReadyFor → the resolver above).
	s.engine.SetReadiness(func() bool {
		s.cfgMu.Lock()
		defer s.cfgMu.Unlock()
		return s.llmOn
	})
	s.engine.SetProxyFailureHandler(s.handleProxyFailure)
	if m.traffic != nil {
		m.traffic.SetUpstreamFailureHandler(s.handleProxyTrafficFailure)
	}
	// Wire live service API keys (2Captcha, Firecrawl, Tavily, Brave, SearXNG),
	// live service integration prompts, and Task <-> Chat live callback bridge.
	agent.ExtraServiceEnv = s.serviceEnvPairs
	agent.ServiceIntegrationsNote = s.serviceIntegrationsNote
	agent.ConversationContextNote = func(sessionID string) string {
		if !strings.HasPrefix(sessionID, "conv-") {
			return ""
		}
		cid, err := strconv.ParseInt(strings.TrimPrefix(sessionID, "conv-"), 10, 64)
		if err != nil || cid <= 0 {
			return ""
		}
		return s.conversationLinkedTasksContext(cid)
	}
	m.SetTaskChatEventHandler(s.triggerTaskChatSyncAsync)

	// Wire DB-stored prompt templates into the agents (new approach S3.3 / S5a). With no
	// override row, agents keep their built-in defaults -- behavior is unchanged.
	if m.pg != nil {
		agent.OpsecEnabled = func() bool { return m.pg.GetBool(settingOpsecEnabled, true) }
		agent.PromptOverride = func(key string) (string, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil {
				return "", false
			}
			t, err := m.pg.CurrentPrompt(a.ID)
			if err != nil || t == "" {
				return "", false
			}
			if key == "reporter" && m.pg.GetBool(settingBrowserScreenshot, false) {
				t += `

[Report Step Screenshots Enabled]
When writing reports, for each reproduction step with a real HTTP page that is still accessible, use browser MCP's browser_navigate and browser_take_screenshot to capture page evidence. Only navigate to target URLs that appear in vulnerability evidence; do not expand the test scope on your own. Save screenshots to findings/screenshots/ directory under the current working directory, using filename format finding-<finding_id>-step-<n>.png; after confirming the file exists, use **workspace-relative paths** uniformly in Markdown images for the corresponding step: ![Step <n> Screenshot](findings/screenshots/finding-<finding_id>-step-<n>.png). Do not use absolute paths, workspace://, file://, and do not mix relative and absolute paths; all screenshots in the report must use this one format. If screenshot fails, state it honestly; do not use placeholders or pass off screenshot descriptions as images.`
			}
			return t, true
		}
		// Wire DB-stored wrap-up (settlement) prompts. Empty column → built-in default.
		agent.WrapupOverride = func(key string) (string, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil || a.WrapupPrompt == "" {
				return "", false
			}
			return a.WrapupPrompt, true
		}
		// Wire DB-stored wrap-up turn budgets. 0 / missing → built-in per-agent default.
		agent.WrapupMaxTurnsOverride = func(key string) (int, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil || a.WrapupMaxTurns <= 0 {
				return 0, false
			}
			return a.WrapupMaxTurns, true
		}
		// Wire DB-stored extra run budgets (tokens / tool calls). 0 = unlimited.
		agent.BudgetOverride = func(key string) (agent.BudgetLimits, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil {
				return agent.BudgetLimits{}, false
			}
			limits := agent.BudgetLimits{MaxTokens: a.TokenBudget, MaxToolCalls: a.ToolCallBudget}
			return limits, limits.Enabled()
		}
		// Wire DB-stored TASK-TIMEOUT wrap-up prompt/turns (worker/planner). Empty/0 → default.
		agent.WrapupTaskTimeoutOverride = func(key string) (string, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil || a.TaskTimeoutWrapupPrompt == "" {
				return "", false
			}
			return a.TaskTimeoutWrapupPrompt, true
		}
		agent.WrapupTaskTimeoutTurnsOverride = func(key string) (int, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil || a.TaskTimeoutWrapupMaxTurns <= 0 {
				return 0, false
			}
			return a.TaskTimeoutWrapupMaxTurns, true
		}
		wireAgentAugment(m.pg, s.skillDir, s.hostTools, s.m.OutboundProxyAddr) // 可见 skills/MCP + 流量/编排 host 工具装配进 agent 工具集
		domainReg := buildDomainReg(m.Assets(), m.pg)
		wireTools(m.pg, domainReg)        // 内置工具表：按 agent 过滤 + 覆盖描述/schema + 注入默认值
		toolErrorHook = s.handleToolError // repeated tool failures → automatic Agent Requests
		seedPrompts(m.pg)                 // 内置 agent 默认提示词正文播种进 agent_prompts(仅空时)
		s.seedOrchestrationTools()        // P2 跨任务编排工具 seed 进 tools 表(可按 agent 绑定)
		if err := s.seedFindingRetester(); err != nil {
			log.Printf("[retester] seed: %v", err)
		}
		go s.evidenceStore().RunGC(s.ctx)
		s.seedPythonInterpreter() // 自定义脚本工具:开机检测 python 解释器入库(仅空时)
		// Calendar scheduler starts after persisted tasks are restored.
		// 漏洞 IM 推送投递引擎。与 Scheduler 并列但独立：推送的实时性要求(3s)
		// 与触发器的业务节奏不同，且两者失败互不牵连——推送卡住不该影响 agent 触发。
		go newNotifier(s).Run(s.ctx)
		// Fill the tool cache for any enabled MCP that has none yet (notably the
		// seeded browser MCP on first run). Async so it never blocks startup.
		go s.discoverEmptyMCPsOnStartup()
		logSink.SetDB(s.ctx, m.pg) // restore last 100 log rows and enable async persistence
	}
	// precedence: persisted DB config > env.
	if cfg, ok := s.loadLLMConfig(); ok {
		if err := s.applyLLM(cfg); err != nil {
			log.Printf("[engine] saved LLM config init failed — engine idle: %v", err)
		} else {
			log.Printf("[engine] LLM configured from DB: %s / %s", cfg.Provider(), cfg.Model)
		}
	} else if cfg, ok := agent.FromEnv(); ok {
		if err := s.applyLLM(cfg); err != nil {
			log.Printf("[engine] env provider init failed — engine idle: %v", err)
		} else {
			log.Printf("[engine] LLM configured from env: %s / %s", cfg.Provider(), cfg.Model)
		}
	} else {
		log.Printf("[engine] no LLM provider configured — engine idle until set via /api/llm or env")
	}
	s.restoreTaskRuntimes()
	s.ensureProxySupervisor()
	s.proxyPoolWG.Add(1)
	go func() { defer s.proxyPoolWG.Done(); s.runProxyPoolSupervisor(s.ctx) }()
	s.startProxyScraperSupervisor(s.ctx)
	go s.reconcileConcurrency()
	s.startTaskArchiveWorker()
	if m.pg != nil {
		agent.CredentialRecorded = func() {
			select {
			case s.credentialWake <- struct{}{}:
			default:
			}
		}
		s.seedCredentialProcessor()
		go s.runCredentialProcessor(s.ctx)
	}
	s.wireInterceptReviewer()     // LLM 兜底审批:未命中拦截规则的命令交给模型判定
	s.restoreInFlightAgentTurns() // seamlessly resume active Chat & Task-MainAgent sessions across live updates
	return s
}

// Close cancels server background workers and waits for task runtimes and proxy
// pool supervision to stop before Manager closes the DB.
func (s *Server) Close() {
	if s != nil {
		closeCause := error(context.Canceled)
		if IsLiveUpdateRestart() {
			s.persistActiveTurnsForLiveUpdate()
			closeCause = agent.AbortLiveUpdateReload
		}
		s.chatMu.Lock()
		for _, cancel := range s.chatCancel {
			if cancel != nil {
				cancel(closeCause)
			}
		}
		s.chatMu.Unlock()
		if s.cancel != nil {
			s.cancel()
		}
		s.engine.ShutdownWithCause(closeCause)
		s.proxyPoolWG.Wait()
		if s.c2srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = s.c2srv.Shutdown(ctx)
			cancel()
		}
		if s.c2mgr != nil {
			_ = s.c2mgr.Close()
		}
		s.stopPhishListener()
	}
}

// Restored deadline and worker loops must inherit the same context as new tasks,
// including the side-question checkpoint publisher installed during startup.
func (s *Server) restoreTaskRuntimes() {
	m := s.m
	// reload tasks persisted on disk so the task list survives a restart, and
	// restore persisted paused state (so a task paused before restart stays paused).
	for _, t := range m.LoadExisting() {
		lifecycle := t.lifecycleSnapshot()
		// clear stale 'running' intents from a prior crash/restart (no live worker
		// owns them) so they re-claim instead of spinning forever in the UI.
		if n, _ := t.Store.ResetRunningIntents(); n > 0 {
			log.Printf("[engine] task %s 重置 %d 个残留 running 意图为 open", t.ID, n)
		}
		if lifecycle.Paused {
			s.engine.Pause(t.ID, agent.AbortPausedOnReload)
		}
		// 任务级超时:为每个未终态、带 timeout 的任务起 deadline 协调器,独立于 planner/worker
		// loop——非活跃任务重启后也能在到点后被收尾(deadline 已过则立即走收尾时序)。
		if !isTerminalStatus(lifecycle.Status) {
			s.engine.startDeadlineCoordinator(s.ctx, t)
		}
	}
	go newScheduler(s).Run(s.ctx)
	// Restore every task that had already been admitted before shutdown. Starting
	// only the active UI task left other non-queued tasks counted as concurrency
	// occupants without live loops, which could permanently block the persistent
	// FIFO. Paused loops remain idle; queued tasks are admitted below as slots allow.
	for _, t := range m.List() {
		lifecycle := t.lifecycleSnapshot()
		if !lifecycle.Queued && !isTerminalStatus(lifecycle.Status) {
			s.engine.Run(s.ctx, t)
		}
	}
}

// agentMaxTurns returns the configured max_turns for an agent key (0 = unlimited,
// also the fallback when no DB or no row).
func (s *Server) agentMaxTurns(key string) int {
	if s.m.pg == nil {
		return 0
	}
	a, err := s.m.pg.GetAgentByKey(key)
	if err != nil || a == nil {
		return 0
	}
	return a.MaxTurns
}

// agentRunSeconds returns the configured wall-clock run budget (seconds) for an
// agent key (0 = unlimited; 1200 fallback when no DB or no row, matching schema).
func (s *Server) agentRunSeconds(key string) int {
	if s.m.pg == nil {
		return 1200
	}
	a, err := s.m.pg.GetAgentByKey(key)
	if err != nil || a == nil {
		return 1200
	}
	return a.RunSecs
}

// loadLLMConfig reads the active LLM profile from PG (llm_profiles).
func (s *Server) loadLLMConfig() (agent.Config, bool) {
	p, err := s.m.pg.ActiveProfile()
	if err != nil || p == nil {
		return agent.Config{}, false
	}
	if p.Format == "jev" {
		return agent.Config{}, false
	}
	cfg := agent.ConfigFrom(p.Format, p.Model, p.BaseURL, p.APIKey, p.Proxy)
	cfg.RatePerSecond, cfg.RatePerMinute = p.RatePerSecond, p.RatePerMinute
	cfg.ContextWindowK = p.ContextWindowK
	cfg.ThinkingType = p.ThinkingType
	cfg.ReasoningEffort = p.ReasoningEffort
	cfg.Stream = p.Streaming
	cfg.MaxTokens, cfg.MaxTokensField = p.MaxTokens, p.MaxTokensField
	cfg.SessionHeaderKey = p.SessionHeaderKey
	s.applyProfileRetry(&cfg, p)
	if cfg.APIKey == "" {
		return cfg, false
	}
	s.cfgMu.Lock()
	s.llmProf = p.Name
	s.cfgMu.Unlock()
	return cfg, true
}

// saveLLMConfig persists the LLM config as the active "default" profile in PG.
func (s *Server) saveLLMConfig(cfg agent.Config) error {
	if cfg.Jev || cfg.Provider() == "jev" {
		return db.ErrJevProfileJudgeOnly
	}
	// cfg.Provider() returns one of the chat format strings
	// (anthropic / openai / openai-responses), matching the DB CHECK constraint;
	// Jev is intentionally handled by the dedicated intercept path.
	format := cfg.Provider()
	var id int64
	// 这个 legacy 端点的请求体不含轮询/收发/输出上限参数,故把库里已存的值原样带回 —
	// 否则每次保存都会把 profile 的 priority、pool_exclude、streaming 以及输出上限
	// (max_tokens / max_tokens_field)悄悄重置成零值。
	var priority int
	var poolExclude bool
	streaming := true // 旧库/新建默认流式
	var maxTokens int
	var maxTokensField string
	var sessionHeaderKey string
	var retry db.RetryOverride
	if profs, _ := s.m.pg.ListProfiles(); profs != nil {
		for _, p := range profs {
			if p.Name == "default" {
				id, priority, poolExclude, streaming = p.ID, p.Priority, p.PoolExclude, p.Streaming
				maxTokens, maxTokensField = p.MaxTokens, p.MaxTokensField
				sessionHeaderKey = p.SessionHeaderKey
				retry = p.Retry
				break
			}
		}
	}
	newID, err := s.m.pg.SaveProfile(&db.LLMProfile{
		ID: id, Name: "default", Format: format, Model: cfg.Model, BaseURL: cfg.BaseURL, Proxy: cfg.Proxy,
		APIKey: cfg.APIKey, RatePerSecond: cfg.RatePerSecond, RatePerMinute: cfg.RatePerMinute,
		ContextWindowK: cfg.ContextWindowK, ThinkingType: cfg.ThinkingType, ReasoningEffort: cfg.ReasoningEffort, IsDefault: true,
		Priority: priority, PoolExclude: poolExclude, Streaming: streaming,
		MaxTokens: maxTokens, MaxTokensField: maxTokensField, SessionHeaderKey: sessionHeaderKey,
		Retry: retry,
	})
	if err != nil {
		return err
	}
	return s.m.pg.SetActiveProfile(newID)
}

// reapplyActiveProfile hot-reloads the engine from the active DB profile so that
// saving or activating a profile takes effect without a restart. Best-effort:
// logs on failure and leaves the running engine untouched.
func (s *Server) reapplyActiveProfile() {
	cfg, ok := s.loadLLMConfig()
	if !ok {
		return
	}
	if err := s.applyLLM(cfg); err != nil {
		log.Printf("[engine] reapply active profile failed: %v", err)
		return
	}
	log.Printf("[engine] LLM reapplied from active profile: %s / %s", cfg.Provider(), cfg.Model)
}

// webSearchFor gates the global web-search opts (backend/key) by an agent's own
// web_search flag: the backend/key come from the global config, each agent decides on/off.
func (s *Server) webSearchFor(key string) agent.WebSearchOpts {
	o := s.m.WebSearchOpts()
	if a, err := s.m.pg.GetAgentByKey(key); err != nil || a == nil || !a.WebSearch {
		o.Enabled = false
	}
	return o
}

// nonStreamingResolver returns a resolver capturing a profile's streaming choice.
// The agents read it per run; a profile change rebuilds the agents (applyLLM),
// so the captured value is always the one in effect for this build.
func nonStreamingResolver(cfg agent.Config) func() bool {
	nonStreaming := !cfg.Stream
	return func() bool { return nonStreaming }
}

// maxTokensResolver mirrors nonStreamingResolver for the per-reply output cap.
func maxTokensResolver(cfg agent.Config) func() int {
	maxTokens := cfg.MaxTokens
	return func() int { return maxTokens }
}

// applyLLM (re)builds the planner/worker/main-agent from cfg and installs them on
// the running engine as the GLOBAL active pair. Safe to call at runtime (UI configures LLM).
func (s *Server) applyLLM(cfg agent.Config) error {
	if cfg.Jev {
		return fmt.Errorf("Jev System One 仅可用于拦截判定模型，不能作为聊天 provider")
	}
	var prov llm.Provider
	// A persisted active profile must use the same cached provider as task chains
	// and Agent bindings, otherwise each path owns a separate rate limiter.
	if active, _ := s.m.pg.ActiveProfile(); active != nil {
		if activeCfg, ok := s.loadProfileConfig(active.ID); ok && activeCfg == cfg {
			prov, _, _ = s.providerForProfile(active.ID)
		}
	}
	if prov == nil {
		var err error
		prov, err = cfg.NewProviderWithLimiter(s.requestLimiterForProfile(0))
		if err != nil {
			return err
		}
		// Non-persisted/env configs do not have a profile cache key.
		s.cfgMu.Lock()
		profName := s.llmProf
		s.cfgMu.Unlock()
		prov = llmrec.Wrap(prov, s.m.PG(), cfg.Model, profName, cfg.ThinkingType, cfg.ReasoningEffort, s.m.LLMRecordEnabled)
		prov = bindSideProvider(prov, cfg, 0, profName)
	}
	s.cfgMu.Lock()
	s.llmDirect = prov
	s.cfgMu.Unlock()
	// LLM 轮询(默认关):把激活配置包进故障转移链,当前配置不可用时自动切下一个。
	// 只影响「走全局激活配置」的这条路径——agent 绑定 / 任务 pin 的走 providerForProfile,
	// 默认仍然独占该配置(见 poolForBinding)。关闭或无备选时返回原 provider,行为不变。
	if act, err := s.m.pg.ActiveProfile(); err == nil && act != nil {
		prov = s.poolForActive(act.ID, prov, cfg)
	}
	// No global planner/worker pair: every task runs on its own task-routed pair
	// (agentsForTask), resolved through the engine's authoritative resolver. Global
	// readiness (Ready()/llm_configured) is reported from s.llmOn, set below.

	tx := transcript.NewStore(filepath.Join(s.m.dir, "transcripts"))
	win := cfg.CompactionWindow()
	// chat stays the GLOBAL fallback since one ChatAgent serves many agent keys — its
	// per-agent binding is resolved at Chat time (runConversationSync →
	// chatAgentForProfile). The main-agent has no global instance: each task builds its
	// own via agentsForTask (task-routed), so nothing is constructed for it here.
	s.cfgMu.Lock()
	// chat agent serves MANY custom agents by key → it holds the GLOBAL opts
	// (backend/key) and gates Enabled per-conversation-agent at Chat time. 对话始终用激活配置。
	s.chatAgent = agent.NewChatAgent(prov, cfg.Model, s.m.dir, tx, win) // chat page runner
	s.chatAgent.SetProxy(s.m.SessionProxyAddr(), s.m.ProxyCACert())
	s.chatAgent.SetProxyProvider(s.m.SessionProxyAddr)
	s.chatAgent.SetWebFetchProxyProvider(s.m.WebFetchProxyAddr)
	s.chatAgent.SetOutboundProxyCheck(s.m.HasOutboundProxy)
	s.chatAgent.SetWebSearch(s.m.WebSearchOpts())
	s.chatAgent.SetGuard(s.chatGuard())
	s.chatAgent.SetNonStreaming(nonStreamingResolver(cfg))
	s.chatAgent.SetMaxTokens(maxTokensResolver(cfg))
	s.chatAgent.SetNoaEnabled(s.m.NoaCompactionEnabled) // 实验功能:noa 上下文压缩(每 run 读)
	s.llmProv = prov
	s.llmCfg = cfg
	s.llmOn = true
	s.cfgMu.Unlock()
	s.profMu.Lock()
	s.profChatAgents = map[int64]*agent.ChatAgent{}
	s.profMu.Unlock()
	s.invalidateTaskAgents()

	// wake the active task so a task created while idle starts exploring.
	if t := s.m.ActiveTask(); t != nil {
		t.Notify()
	}
	return nil
}

// loadProfileConfig builds an agent.Config from a specific profile id (with its key).
// ok=false when the profile is missing or has no api key.
func (s *Server) loadProfileConfig(id int64) (agent.Config, bool) {
	p, err := s.m.pg.ProfileByID(id)
	if err != nil || p == nil {
		return agent.Config{}, false
	}
	return s.profileConfig(p)
}

func (s *Server) profileConfig(p *db.LLMProfile) (agent.Config, bool) {
	if p == nil {
		return agent.Config{}, false
	}
	if p.Format == "jev" {
		return agent.Config{}, false
	}
	cfg := agent.ConfigFrom(p.Format, p.Model, p.BaseURL, p.APIKey, p.Proxy)
	cfg.RatePerSecond, cfg.RatePerMinute = p.RatePerSecond, p.RatePerMinute
	cfg.ContextWindowK = p.ContextWindowK
	cfg.ThinkingType = p.ThinkingType
	cfg.ReasoningEffort = p.ReasoningEffort
	cfg.Stream = p.Streaming
	cfg.MaxTokens, cfg.MaxTokensField = p.MaxTokens, p.MaxTokensField
	cfg.SessionHeaderKey = p.SessionHeaderKey
	s.applyProfileRetry(&cfg, p)
	if cfg.APIKey == "" {
		return cfg, false
	}
	return cfg, true
}

// effectiveProfileForAgent resolves the LLM profile id an agent should run on, by
// precedence: agent binding (agents.llm_profile_id) → pin (task/conversation) → nil
// (caller falls back to the global active profile). A binding to a deleted profile
// can't happen (FK ON DELETE SET NULL); an otherwise-invalid one is dropped downstream
// by loadProfileConfig, letting the caller fall back.
func (s *Server) effectiveProfileForAgent(agentKey string, pinID *int64) *int64 {
	if s.m.pg != nil && agentKey != "" {
		if a, _ := s.m.pg.GetAgentByKey(agentKey); a != nil && a.LLMProfileID != nil {
			return a.LLMProfileID
		}
	}
	return pinID
}

// resolveChatAgent picks the ChatAgent for one conversation: the agent's own
// binding or this conversation's chosen profile first, the global active config
// only as a fallback. Both the send precheck and the background runner MUST use
// this — resolving differently in the two paths is how a conversation that had
// picked a valid profile still got rejected with "LLM 未配置" when no global
// config was active.
func (s *Server) resolveChatAgent(c *db.Conversation) *agent.ChatAgent {
	ca := s.chatAgentRef()
	if eff := s.effectiveProfileForAgent(c.AgentKey, c.LLMProfileID); eff != nil {
		if pa := s.chatAgentForProfile(*eff); pa != nil {
			ca = pa
		}
	}
	return ca
}

// chatUnavailableReason explains why no ChatAgent could be resolved, so the user
// knows whether to add a config, activate one, or pick one for this conversation
// — rather than a flat "not configured" that hides which of those it is.
func (s *Server) chatUnavailableReason() string {
	if s.m.pg != nil {
		if profiles, err := s.m.pg.ListProfiles(); err == nil && len(profiles) == 0 {
			return "No LLM profile configured: please go to System -> LLM to add a model profile"
		}
		if active, err := s.m.pg.ActiveProfile(); err == nil && active == nil {
			return "No active LLM profile: please go to System -> LLM to activate one, or select a profile for this conversation"
		}
	}
	return "LLM not ready: please check System -> LLM to ensure an active model profile is configured"
}

// providerForProfile returns a cached provider+cfg for a profile id, so every agent
// bound/pinned to the same profile shares one provider instance (one rate limiter).
// ok=false when the profile is missing/invalid; pinned callers surface that error
// while legacy callers retain their existing fallback behavior.
func (s *Server) providerForProfile(id int64) (llm.Provider, agent.Config, bool) {
	s.provCacheMu.Lock()
	if s.provByProfile == nil {
		s.provByProfile = make(map[int64]*provEntry)
	}
	if e := s.provByProfile[id]; e != nil {
		if e.jev {
			s.provCacheMu.Unlock()
			return nil, agent.Config{}, false
		}
		s.provCacheMu.Unlock()
		return e.prov, e.cfg, true
	}
	generation := s.provCacheGen
	s.provCacheMu.Unlock()
	// Only a cache miss reaches the DB. This preserves an already-built chat
	// provider during a transient profile lookup failure and avoids a query for
	// every agent/task resolution.
	profile, err := s.m.pg.ProfileByID(id)
	if err != nil || profile == nil {
		return nil, agent.Config{}, false
	}
	if profile.Format == "jev" {
		// Cache the negative result too. Profile writes/activation invalidate this
		// generation, while a transient DB error on a cached chat profile above
		// still returns that already-built provider.
		s.provCacheMu.Lock()
		if generation == s.provCacheGen {
			if s.provByProfile == nil {
				s.provByProfile = map[int64]*provEntry{}
			}
			s.provByProfile[id] = &provEntry{jev: true}
		}
		s.provCacheMu.Unlock()
		return nil, agent.Config{}, false
	}
	cfg, ok := s.profileConfig(profile)
	if !ok {
		return nil, agent.Config{}, false
	}
	s.provCacheMu.Lock()
	if generation != s.provCacheGen {
		s.provCacheMu.Unlock()
		return s.providerForProfile(id)
	}
	if e := s.provByProfile[id]; e != nil { // lost the race → keep the winner
		if e.jev {
			s.provCacheMu.Unlock()
			return nil, agent.Config{}, false
		}
		s.provCacheMu.Unlock()
		return e.prov, e.cfg, true
	}
	// Building the HTTP client does not perform network I/O. Keep this step
	// under the generation lock so a stale build cannot overwrite the retained
	// limiter's settings after a newer configuration has already been installed.
	prov, err := cfg.NewProviderWithLimiter(s.requestLimiterForProfileLocked(id))
	if err != nil {
		s.provCacheMu.Unlock()
		log.Printf("[engine] build provider for LLM profile %d failed: %v", id, err)
		return nil, agent.Config{}, false
	}
	if profile != nil {
		prov = llmrec.Wrap(prov, s.m.PG(), cfg.Model, profile.Name, cfg.ThinkingType, cfg.ReasoningEffort, s.m.LLMRecordEnabled)
		prov = bindSideProvider(prov, cfg, id, profile.Name)
	}
	s.provByProfile[id] = &provEntry{prov: prov, cfg: cfg, jev: false}
	log.Printf("[engine] built provider for LLM profile %d (%s / %s)", id, cfg.Provider(), cfg.Model)
	s.provCacheMu.Unlock()
	return prov, cfg, true
}

func (s *Server) requestLimiterForProfile(id int64) *agent.RequestLimiter {
	s.provCacheMu.Lock()
	defer s.provCacheMu.Unlock()
	return s.requestLimiterForProfileLocked(id)
}

func (s *Server) requestLimiterForProfileLocked(id int64) *agent.RequestLimiter {
	if s.requestLimiters == nil {
		s.requestLimiters = make(map[int64]*agent.RequestLimiter)
	}
	if s.requestLimiters[id] == nil {
		s.requestLimiters[id] = &agent.RequestLimiter{}
	}
	return s.requestLimiters[id]
}

// chatAgentForProfile returns a ChatAgent built from a specific LLM profile, cached
// per profile id. Returns nil if the profile is missing or has no API key.
func (s *Server) chatAgentForProfile(id int64) *agent.ChatAgent {
	s.profMu.Lock()
	cached := s.profChatAgents[id]
	s.profMu.Unlock()
	if cached != nil {
		return cached
	}
	prov, cfg, ok := s.providerForProfile(id)
	if !ok {
		return nil
	}
	tx := transcript.NewStore(filepath.Join(s.m.dir, "transcripts"))
	ca := agent.NewChatAgent(s.poolForBinding(id, prov, cfg), cfg.Model, s.m.dir, tx, cfg.CompactionWindow())
	ca.SetProxy(s.m.SessionProxyAddr(), s.m.ProxyCACert())
	ca.SetProxyProvider(s.m.SessionProxyAddr)
	ca.SetWebFetchProxyProvider(s.m.WebFetchProxyAddr)
	ca.SetOutboundProxyCheck(s.m.HasOutboundProxy)
	ca.SetWebSearch(s.m.WebSearchOpts())
	ca.SetGuard(s.chatGuard())
	ca.SetNonStreaming(nonStreamingResolver(cfg))
	ca.SetMaxTokens(maxTokensResolver(cfg))
	ca.SetNoaEnabled(s.m.NoaCompactionEnabled) // 实验功能:noa 上下文压缩(每 run 读)
	s.profMu.Lock()
	if ex := s.profChatAgents[id]; ex != nil { // lost the race → keep the winner
		ca = ex
	} else {
		s.profChatAgents[id] = ca
	}
	s.profMu.Unlock()
	return ca
}

// invalidateProfileAgents drops the per-profile ChatAgent + provider caches so a profile
// save/activate/delete — or an agent's binding change — rebuilds pinned tasks' agents
// (and re-resolves each agent's bound model) on their next round.
func (s *Server) invalidateProfileAgents() {
	s.profMu.Lock()
	s.profChatAgents = map[int64]*agent.ChatAgent{}
	s.profMu.Unlock()
	s.provCacheMu.Lock()
	s.provCacheGen++
	s.provByProfile = map[int64]*provEntry{}
	s.provCacheMu.Unlock()
	s.invalidateTaskAgents()
}

func (s *Server) chatAgentRef() *agent.ChatAgent {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return s.chatAgent
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerSideRoutes(mux)

	// Register Proxy Pool v2 API endpoints
	s.registerProxyPoolV2Routes(mux)

	// Tool Recipes API (CyberStrikeAI-style)
	mux.HandleFunc("GET /api/v2/recipes", s.handleListRecipes)
	mux.HandleFunc("GET /api/v2/recipes/{id}", s.handleGetRecipe)
	mux.HandleFunc("GET /api/v2/recipes/categories", s.handleRecipeCategories)
	mux.HandleFunc("POST /api/v2/recipes/search", s.handleSearchRecipes)

	// Fact Graph API (sapper-v2 style)
	mux.HandleFunc("GET /api/v2/facts", s.handleListFacts)
	mux.HandleFunc("POST /api/v2/facts", s.handleCreateFact)
	mux.HandleFunc("GET /api/v2/facts/{id}", s.handleGetFact)
	mux.HandleFunc("PATCH /api/v2/facts/{id}", s.handleUpdateFact)
	mux.HandleFunc("DELETE /api/v2/facts/{id}", s.handleDeleteFact)
	mux.HandleFunc("POST /api/v2/facts/search", s.handleSearchFacts)
	mux.HandleFunc("GET /api/v2/facts/stats", s.handleFactStats)
	mux.HandleFunc("POST /api/v2/facts/link", s.handleLinkFacts)

	// TLS Fingerprinting API
	mux.HandleFunc("GET /api/v2/tls/specs", s.handleTLSSpecs)
	mux.HandleFunc("GET /api/v2/tls/current", s.handleTLSCurrent)

	// Tool Catalog & Execution API (HexStrike-inspired)
	mux.HandleFunc("GET /api/v2/tools", s.handleListTools)
	mux.HandleFunc("GET /api/v2/tools/{id}", s.handleGetTool)
	mux.HandleFunc("GET /api/v2/tools/categories", s.handleToolCategories)
	mux.HandleFunc("POST /api/v2/tools/search", s.handleSearchTools)
	mux.HandleFunc("POST /api/v2/tools/execute", s.handleExecuteTool)
	mux.HandleFunc("GET /api/v2/tools/execution/{id}", s.handleGetExecution)
	mux.HandleFunc("GET /api/v2/tools/history", s.handleExecutionHistory)

	// Target Connectors API (HackingBuddyGPT-inspired)
	mux.HandleFunc("POST /api/v2/targets/connect/ssh", s.handleConnectSSH)
	mux.HandleFunc("POST /api/v2/targets/connect/winrm", s.handleConnectWinRM)
	mux.HandleFunc("DELETE /api/v2/targets/{id}", s.handleDisconnectTarget)
	mux.HandleFunc("GET /api/v2/targets", s.handleListTargets)
	mux.HandleFunc("POST /api/v2/targets/{id}/execute", s.handleTargetExecute)
	mux.HandleFunc("POST /api/v2/targets/{id}/sftp/upload", s.handleSFTPUpload)
	mux.HandleFunc("POST /api/v2/targets/{id}/sftp/download", s.handleSFTPDownload)

	// Auth routes — exempt from JWT check (handled in requireAuth)
	mux.HandleFunc("GET /api/auth/status", s.authStatus)
	mux.HandleFunc("POST /api/auth/turnstile-verify", s.authTurnstileVerify)
	mux.HandleFunc("POST /api/auth/init", s.authInit)
	mux.HandleFunc("POST /api/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/auth/change-password", s.authChangePassword)
	mux.HandleFunc("GET /api/basic-auth/check", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/settings/basic-auth", s.getBasicAuthSettings)
	mux.HandleFunc("PUT /api/settings/basic-auth", s.saveBasicAuthSettings)

	// Commercial Licensing, White-Label Branding & Client Deliverable Reports
	mux.HandleFunc("GET /api/branding", s.handleGetPublicBranding)
	mux.HandleFunc("GET /api/commercial/status", s.handleGetCommercialStatus)
	mux.HandleFunc("PUT /api/commercial/branding", s.handlePutCommercialBranding)
	mux.HandleFunc("POST /api/commercial/license", s.handlePostCommercialLicense)
	mux.HandleFunc("GET /api/deliverables/report", s.handleExportDeliverableReport)

	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("/api/oast-cb/", s.handleCallbackReceipt)
	if mgr := s.c2Manager(); mgr != nil {
		c2.RegisterHandler(mux, s.c2Handler)
		c2.RegisterConsole(mux, s.c2Console)
	}
	mux.HandleFunc("GET /api/version", s.version)
	mux.HandleFunc("GET /api/stats", s.stats)
	mux.HandleFunc("GET /api/system/metrics", s.systemMetrics)
	mux.HandleFunc("GET /api/logs", s.getLogs)
	mux.HandleFunc("GET /api/logs/history", s.getLogsHistory)
	mux.HandleFunc("GET /api/logs/stream", s.streamLogs)

	// One-click in-app updates & automatic Git live-sync endpoints
	mux.HandleFunc("GET /api/update/maintenance", s.handleMaintenanceStatus)
	mux.HandleFunc("POST /api/update/webhook", s.handleTriggerGitSync)
	mux.HandleFunc("POST /api/update/git-sync", s.handleTriggerGitSync)
	mux.HandleFunc("GET /api/update/settings", s.getUpdateSettings)
	mux.HandleFunc("PUT /api/update/settings", s.putUpdateSettings)
	mux.HandleFunc("GET /api/update/check", s.updateCheck)
	mux.HandleFunc("POST /api/update/apply", s.updateApply)
	mux.HandleFunc("POST /api/update/rollback", s.updateRollback)
	mux.HandleFunc("GET /api/update/stream", s.updateStream)

	mux.HandleFunc("GET /api/tasks", s.listTasks)
	mux.HandleFunc("POST /api/tasks", s.createTask)
	mux.HandleFunc("GET /api/schedules", s.listSchedules)
	mux.HandleFunc("POST /api/schedules", s.createSchedule)
	mux.HandleFunc("GET /api/schedules/{id}", s.getSchedule)
	mux.HandleFunc("PATCH /api/schedules/{id}", s.updateSchedule)
	mux.HandleFunc("PATCH /api/schedules/{id}/remark", s.updateScheduleMetadata)
	mux.HandleFunc("PATCH /api/schedules/{id}/metadata", s.updateScheduleMetadata)
	mux.HandleFunc("DELETE /api/schedules/{id}", s.deleteSchedule)
	mux.HandleFunc("POST /api/schedules/{id}/pause", s.pauseSchedule)
	mux.HandleFunc("POST /api/schedules/{id}/resume", s.resumeSchedule)
	mux.HandleFunc("POST /api/schedules/{id}/run-now", s.runScheduleNow)
	mux.HandleFunc("GET /api/task-categories", s.pgListTaskCategories)
	mux.HandleFunc("POST /api/task-categories", s.pgCreateTaskCategory)
	mux.HandleFunc("PATCH /api/task-categories/{id}", s.pgRenameTaskCategory)
	mux.HandleFunc("DELETE /api/task-categories/{id}", s.pgDeleteTaskCategory)
	mux.HandleFunc("POST /api/tasks/category/batch", s.updateTasksCategoryBatch)
	mux.HandleFunc("GET /api/task-templates", s.pgListTaskTemplates)
	mux.HandleFunc("POST /api/task-templates", s.pgCreateTaskTemplate)
	mux.HandleFunc("PATCH /api/task-templates/{id}", s.pgUpdateTaskTemplate)
	mux.HandleFunc("DELETE /api/task-templates/{id}", s.pgDeleteTaskTemplate)
	mux.HandleFunc("GET /api/tasks/{id}", s.getTask)
	mux.HandleFunc("PATCH /api/tasks/{id}", s.updateTaskMetadata)
	mux.HandleFunc("PATCH /api/tasks/{id}/category", s.updateTaskCategory)
	// 任务级资产拦截/允许规则
	mux.HandleFunc("GET /api/tasks/{id}/intercept-rules", s.taskInterceptListRules)
	mux.HandleFunc("POST /api/tasks/{id}/intercept-rules", s.taskInterceptCreateRule)
	mux.HandleFunc("PUT /api/tasks/{id}/intercept-rules/{rid}", s.taskInterceptUpdateRule)
	mux.HandleFunc("DELETE /api/tasks/{id}/intercept-rules/{rid}", s.taskInterceptDeleteRule)
	mux.HandleFunc("POST /api/tasks/{id}/intercept-rules/{rid}/toggle", s.taskInterceptToggleRule)
	mux.HandleFunc("POST /api/tasks/control/batch", s.controlTasksBatch)
	mux.HandleFunc("GET /api/task-archives", s.listTaskArchives)
	mux.HandleFunc("GET /api/task-archives/{id}", s.getTaskArchive)
	mux.HandleFunc("POST /api/tasks/{id}/archive", s.queueTaskArchive)
	mux.HandleFunc("POST /api/tasks/archive/batch", s.queueTaskArchivesBatch)
	mux.HandleFunc("POST /api/task-archives/{id}/restore", s.queueTaskArchiveRestore)
	mux.HandleFunc("POST /api/task-archives/restore/batch", s.restoreTaskArchivesBatch)
	mux.HandleFunc("DELETE /api/task-archives/{id}", s.queueTaskArchiveDelete)
	mux.HandleFunc("POST /api/task-archives/delete/batch", s.deleteTaskArchivesBatch)
	mux.HandleFunc("GET /api/tasks/{id}/coverage", s.taskCoverage)
	mux.HandleFunc("GET /api/tasks/{id}/coverage-graph", s.taskCoverageGraph)
	// Asset relationships are read directly from the asset store. This action
	// only runs the topology explanation and produces the asset/network reports.
	mux.HandleFunc("POST /api/tasks/{id}/topology-mapping", s.taskAssetMapping)
	mux.HandleFunc("GET /api/tasks/{id}/topology-mapping/status", s.taskAssetMappingStatus)
	// Keep the old paths for clients from earlier builds.
	mux.HandleFunc("POST /api/tasks/{id}/asset-mapping", s.taskAssetMapping)
	mux.HandleFunc("GET /api/tasks/{id}/asset-mapping/status", s.taskAssetMappingStatus)
	mux.HandleFunc("GET /api/tasks/{id}/asset-refs", s.taskAssetRefs)
	mux.HandleFunc("POST /api/tasks/{id}/assets", s.attachTaskAssets)
	mux.HandleFunc("DELETE /api/tasks/{id}/assets/{assetID}", s.detachTaskAsset)
	mux.HandleFunc("GET /api/tasks/{id}/intent-assets", s.taskIntentAssets)

	// 工作空间文件管理器（针对 workDir）
	mux.HandleFunc("GET /api/tasks/{id}/files", s.taskFilesList)
	mux.HandleFunc("GET /api/tasks/{id}/files/all", s.taskFilesAll)
	mux.HandleFunc("GET /api/tasks/{id}/files/read", s.taskFilesServe)
	mux.HandleFunc("GET /api/tasks/{id}/files/download", s.taskFilesServe)
	mux.HandleFunc("GET /api/tasks/{id}/files/preview", s.taskFilesServe)
	mux.HandleFunc("GET /api/tasks/{id}/files/archive", s.taskFilesArchive)
	mux.HandleFunc("GET /api/workspace/list", s.wsList)
	mux.HandleFunc("GET /api/workspace/read", s.wsRead)
	mux.HandleFunc("POST /api/workspace/write", s.wsWrite)
	mux.HandleFunc("POST /api/workspace/mkdir", s.wsMkdir)
	mux.HandleFunc("DELETE /api/workspace/delete", s.wsDelete)
	mux.HandleFunc("GET /api/workspace/download", s.wsDownload)
	mux.HandleFunc("GET /api/workspace/preview", s.wsPreview)
	mux.HandleFunc("POST /api/workspace/upload", s.wsUpload)
	mux.HandleFunc("GET /api/tasks/{id}/scope", s.taskScopeList)
	mux.HandleFunc("POST /api/tasks/{id}/scope", s.taskScopeAdd)
	mux.HandleFunc("DELETE /api/tasks/{id}/scope/{sid}", s.taskScopeDelete)
	mux.HandleFunc("GET /api/tasks/{id}/goals", s.listGoals)                       // 目标管理:列出本任务全部目标
	mux.HandleFunc("POST /api/tasks/{id}/goals", s.addGoal)                        // 目标管理:人工新增目标(复活任务)
	mux.HandleFunc("PATCH /api/tasks/{id}/goals/{gid}", s.editGoal)                // 目标管理:修改目标(复活任务)
	mux.HandleFunc("DELETE /api/tasks/{id}/goals/{gid}", s.deleteGoal)             // 目标管理:硬删除目标(不复活)
	mux.HandleFunc("GET /api/tasks/{id}/constraints", s.listConstraints)           // 约束管理:列出本任务操作约束
	mux.HandleFunc("POST /api/tasks/{id}/constraints", s.addConstraint)            // 约束管理:新增约束(不通知 planner)
	mux.HandleFunc("PATCH /api/tasks/{id}/constraints/{cid}", s.editConstraint)    // 约束管理:修改约束
	mux.HandleFunc("DELETE /api/tasks/{id}/constraints/{cid}", s.deleteConstraint) // 约束管理:删除约束
	mux.HandleFunc("POST /api/tasks/{id}/control", s.control)
	mux.HandleFunc("PUT /api/tasks/{id}/llm", s.updateTaskLLMProfiles)
	mux.HandleFunc("GET /api/tasks/{id}/llm/resolution", s.taskLLMResolutionHandler)
	mux.HandleFunc("POST /api/tasks/{id}/intents/{iid}/control", s.controlIntent)
	mux.HandleFunc("POST /api/tasks/{id}/intents/{iid}/messages", s.sendWorkerMessage)
	mux.HandleFunc("POST /api/tasks/{id}/intents/{iid}/rerun", s.rerunIntent)    // 重跑单条 blocked/exhausted/stopped 意图
	mux.HandleFunc("POST /api/tasks/{id}/intents/rerun-blocked", s.rerunBlocked) // 批量重跑本任务全部 blocked 意图
	mux.HandleFunc("POST /api/active", s.setActive)

	mux.HandleFunc("GET /api/llm", s.getLLM)
	mux.HandleFunc("POST /api/llm", s.setLLM)
	mux.HandleFunc("POST /api/llm/test", s.testLLM)

	// asset system
	mux.HandleFunc("GET /api/assets", s.listAssets)
	mux.HandleFunc("GET /api/assets/counts", s.assetCounts)
	mux.HandleFunc("POST /api/assets", s.insertAssets)
	mux.HandleFunc("DELETE /api/assets", s.deleteAssets)

	// company system
	mux.HandleFunc("GET /api/companies", s.listCompanies)
	mux.HandleFunc("POST /api/companies", s.createCompany)
	mux.HandleFunc("GET /api/companies/{id}", s.getCompany)
	mux.HandleFunc("DELETE /api/companies/{id}", s.deleteCompany)
	mux.HandleFunc("POST /api/companies/{id}/scope", s.addCompanyScope)
	mux.HandleFunc("POST /api/companies/reattribute", s.reattribute)
	mux.HandleFunc("GET /api/artifacts", s.listArtifacts)
	mux.HandleFunc("GET /api/artifacts/counts", s.artifactCounts)
	mux.HandleFunc("POST /api/artifacts", s.uploadArtifact)
	mux.HandleFunc("GET /api/artifacts/{id}", s.getArtifact)
	mux.HandleFunc("GET /api/artifacts/{id}/download", s.serveArtifact)
	mux.HandleFunc("DELETE /api/artifacts/{id}", s.deleteArtifact)

	// Agent capability requests (report_need inbox: System → Agent Requests).
	mux.HandleFunc("GET /api/agent-requests", s.listAgentRequests)
	mux.HandleFunc("GET /api/agent-requests/counts", s.agentRequestCounts)
	mux.HandleFunc("PATCH /api/agent-requests/{id}", s.updateAgentRequest)
	mux.HandleFunc("DELETE /api/agent-requests/{id}", s.deleteAgentRequest)

	mux.HandleFunc("GET /api/exploration/frontier", s.frontier)
	mux.HandleFunc("GET /api/exploration/findings", s.findings)
	mux.HandleFunc("GET /api/exploration/findings/groups", s.findingGroups)
	mux.HandleFunc("GET /api/exploration/finding-cases", s.listFindingCases)
	mux.HandleFunc("POST /api/exploration/finding-cases", s.mergeFindingCase)
	mux.HandleFunc("GET /api/exploration/finding-cases/{id}", s.getFindingCase)
	mux.HandleFunc("GET /api/exploration/finding-cases/{id}/members", s.getFindingCaseMembers)
	mux.HandleFunc("DELETE /api/exploration/finding-cases/{id}/members/{fid}", s.removeFindingCaseMember)
	mux.HandleFunc("PUT /api/exploration/finding-cases/{id}/report", s.updateCaseReport)
	mux.HandleFunc("GET /api/exploration/finding-case-suggestions", s.caseSuggestions)
	mux.HandleFunc("POST /api/exploration/finding-case-suggestions/{id}", s.resolveCaseSuggestion)
	mux.HandleFunc("POST /api/exploration/finding-case-review", s.reviewFindingCases)
	mux.HandleFunc("GET /api/exploration/finding-case-review", s.caseReviewRuns)
	mux.HandleFunc("GET /api/exploration/findings/asset-tree", s.findingAssetTree)
	mux.HandleFunc("GET /api/exploration/findings/stats", s.findingStats)
	mux.HandleFunc("GET /api/exploration/findings/export", s.findingsExport)
	s.registerFindingTraffic(mux)
	s.registerRepeater(mux)
	mux.HandleFunc("GET /api/exploration/findings/{id}", s.getFinding)
	mux.HandleFunc("GET /api/exploration/findings/{id}/lineage", s.findingLineage)
	mux.HandleFunc("POST /api/exploration/findings/{id}/deepen", s.deepenFinding)
	mux.HandleFunc("POST /api/exploration/findings/{id}/generate-report", s.generateFindingReport)
	mux.HandleFunc("GET /api/exploration/findings/{id}/retests", s.listFindingRetests)
	mux.HandleFunc("GET /api/exploration/findings/retests/active", s.listActiveFindingRetests)
	mux.HandleFunc("POST /api/exploration/findings/{id}/retests", s.startFindingRetest)
	mux.HandleFunc("PATCH /api/exploration/findings/{id}", s.patchFinding)
	mux.HandleFunc("DELETE /api/exploration/findings/{id}", s.deleteFinding)
	mux.HandleFunc("GET /api/exploration/intents", s.intents)
	mux.HandleFunc("GET /api/exploration/graph", s.explorationGraph)
	mux.HandleFunc("GET /api/exploration/nodes", s.explorationNodes)
	mux.HandleFunc("GET /api/exploration/activity", s.activity)
	mux.HandleFunc("GET /api/exploration/activity/history", s.activityHistory)
	mux.HandleFunc("GET /api/exploration/main-sessions", s.mainSessions)
	mux.HandleFunc("POST /api/exploration/main-session/new", s.newMainSession)
	mux.HandleFunc("GET /api/exploration/activity/stream", s.streamActivity)
	mux.HandleFunc("GET /api/exploration/activity/{seq}", s.activityDetail)
	mux.HandleFunc("GET /api/exploration/tokens", s.tokenStats)
	mux.HandleFunc("GET /api/tokens/daily", s.tokenDailyStats)
	mux.HandleFunc("GET /api/tokens/conversations", s.conversationTokens)
	mux.HandleFunc("GET /api/tokens/usage", s.pgUsageStats)       // 全局 llm_usage 聚合（仪表盘新版视图）
	mux.HandleFunc("POST /api/tokens/reset", s.pgResetUsageStats) // 重置仪表盘 Token 统计与图表（保留漏洞/资产）

	mux.HandleFunc("GET /api/audit", s.getAudit)
	mux.HandleFunc("POST /api/gc", s.gc)
	mux.HandleFunc("GET /api/traffic", s.getTraffic)
	mux.HandleFunc("GET /api/traffic/hosts", s.getTrafficHosts)
	mux.HandleFunc("DELETE /api/traffic", s.deleteTraffic)
	mux.HandleFunc("DELETE /api/traffic/hosts", s.deleteTrafficHosts)
	mux.HandleFunc("DELETE /api/traffic/all", s.deleteAllTraffic)
	mux.HandleFunc("GET /api/traffic/exchange", s.getTrafficExchange)
	mux.HandleFunc("GET /api/traffic/blob", s.getTrafficBlob)
	mux.HandleFunc("GET /api/commands", s.pgListCommands)
	mux.HandleFunc("GET /api/commands/stats", s.pgToolStats) // 按工具聚合调用次数
	mux.HandleFunc("GET /api/llm/records", s.pgListLLMRecords)
	mux.HandleFunc("DELETE /api/llm/records", s.pgDeleteLLMRecords)
	mux.HandleFunc("GET /api/llm/records/tasks", s.pgLLMTasks)
	mux.HandleFunc("GET /api/llm/records/by-model", s.pgTokenByModel) // 按模型聚合本任务 token 用量
	mux.HandleFunc("GET /api/llm/records/{id}", s.pgGetLLMRecord)
	mux.HandleFunc("GET /api/tasks/{id}/intelligence", s.listIntelligence)
	mux.HandleFunc("GET /api/tasks/{id}/intelligence/{intelID}", s.getIntelligence)
	mux.HandleFunc("PATCH /api/tasks/{id}/intelligence/{intelID}", s.updateIntelligence)
	mux.HandleFunc("POST /api/tasks/{id}/intelligence/{intelID}/credentials/retry", s.retryCredentials)
	mux.HandleFunc("GET /api/tasks/{id}/intelligence/{intelID}/traffic/{trafficID}", s.credentialTrafficDetail)
	mux.HandleFunc("GET /api/assets/{id}/intelligence/{intelID}/traffic/{trafficID}", func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("scope", "assets")
		s.credentialTrafficDetail(w, r)
	})
	mux.HandleFunc("GET /api/assets/{id}/intelligence", func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("scope", "assets")
		s.listIntelligence(w, r)
	})
	mux.HandleFunc("GET /api/assets/{id}/intelligence/{intelID}", func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("scope", "assets")
		s.getIntelligence(w, r)
	})
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	// 漏洞 IM 推送。渠道是「多实例 + 各自过滤规则」的资源，因此独立成一组
	// REST 接口，而不是塞进扁平的 /api/settings 键值里。
	mux.HandleFunc("GET /api/notify/meta", s.notifyMeta)
	mux.HandleFunc("GET /api/notify/channels", s.notifyListChannels)
	mux.HandleFunc("POST /api/notify/channels", s.notifyCreateChannel)
	mux.HandleFunc("PATCH /api/notify/channels/{id}", s.notifyUpdateChannel)
	mux.HandleFunc("DELETE /api/notify/channels/{id}", s.notifyDeleteChannel)
	mux.HandleFunc("POST /api/notify/channels/{id}/test", s.notifyTestChannel)
	mux.HandleFunc("GET /api/notify/deliveries", s.notifyListDeliveries)
	mux.HandleFunc("POST /api/notify/deliveries/{id}/retry", s.notifyRetryDelivery)
	mux.HandleFunc("POST /api/settings/web-search/test", s.testWebSearch)
	// 出口代理连通性测试：发真实请求验证 global_proxy 是否可用，并回显出口 IP。
	mux.HandleFunc("POST /api/settings/proxy/test", s.testEgressProxy)
	mux.HandleFunc("GET /api/settings/proxy-pool", s.getProxyPool)
	mux.HandleFunc("POST /api/settings/proxy-pool/import", s.importProxyPool)
	mux.HandleFunc("PUT /api/settings/proxy-pool/{id}", s.updateProxyPool)
	mux.HandleFunc("DELETE /api/settings/proxy-pool/{id}", s.deleteProxyPool)
	mux.HandleFunc("POST /api/settings/proxy-pool/{id}/test", s.testProxyPoolEntry)
	mux.HandleFunc("POST /api/settings/proxy-pool/test-all", s.testAllProxyPool)
	mux.HandleFunc("POST /api/settings/proxy-pool/{id}/activate", s.activateProxyPool)
	mux.HandleFunc("POST /api/tasks/{id}/proxy/test", s.testTaskProxy)
	mux.HandleFunc("GET /api/report", s.getReport)
	mux.HandleFunc("GET /api/chat/mentions", s.searchChatMentions)
	mux.HandleFunc("POST /api/chat", s.chat)
	mux.HandleFunc("POST /api/chat/upload", s.chatUpload) // 方式1 文件上传:落到会话/任务工作目录 uploads/
	mux.HandleFunc("GET /api/tasks/{id}/chat/status", s.taskChatStatus)
	mux.HandleFunc("POST /api/tasks/{id}/chat/stop", s.stopChat)

	// --- 管理后台 API (PostgreSQL 数据源; 新版数据库与管理后台方案) ---
	mux.HandleFunc("DELETE /api/tasks/{id}", s.pgDeleteTask)
	// Agents
	// conversations (chat page)
	mux.HandleFunc("GET /api/conversations", s.pgListConversations)
	mux.HandleFunc("POST /api/conversations", s.pgCreateConversation)
	mux.HandleFunc("POST /api/conversations/delete/batch", s.pgDeleteConversationsBatch)
	mux.HandleFunc("PATCH /api/conversations/{id}", s.pgRenameConversation)
	mux.HandleFunc("PATCH /api/conversations/{id}/profile", s.pgUpdateConversation)
	mux.HandleFunc("DELETE /api/conversations/{id}", s.pgDeleteConversation)
	mux.HandleFunc("GET /api/conversations/{id}/messages", s.pgConversationMessages)
	mux.HandleFunc("GET /api/conversations/{id}/stream", s.pgConversationStream)
	mux.HandleFunc("POST /api/conversations/{id}/messages", s.pgSendConversationMessage)
	mux.HandleFunc("POST /api/conversations/{id}/stop", s.pgStopConversation)
	mux.HandleFunc("GET /api/conversations/{id}/messages/{seq}", s.pgConversationMsgDetail)

	mux.HandleFunc("GET /api/agents", s.pgListAgents)
	mux.HandleFunc("POST /api/agents", s.pgCreateAgent)
	mux.HandleFunc("GET /api/agents/{key}", s.pgGetAgent)
	mux.HandleFunc("PATCH /api/agents/{key}", s.pgUpdateAgent)
	mux.HandleFunc("DELETE /api/agents/{key}", s.pgDeleteAgent)
	mux.HandleFunc("PUT /api/agents/{key}/config", s.pgSaveAgentConfig)
	mux.HandleFunc("PUT /api/agents/{key}/prompt", s.pgSavePrompt)
	mux.HandleFunc("POST /api/agents/{key}/prompt/reset", s.pgResetPrompt)
	mux.HandleFunc("PUT /api/agents/{key}/wrapup", s.pgSaveWrapup)
	mux.HandleFunc("POST /api/agents/{key}/wrapup/reset", s.pgResetWrapup)
	mux.HandleFunc("PUT /api/agents/{key}/wrapup/task-timeout", s.pgSaveTaskTimeoutWrapup)
	mux.HandleFunc("POST /api/agents/{key}/wrapup/task-timeout/reset", s.pgResetTaskTimeoutWrapup)
	mux.HandleFunc("GET /api/agents/{key}/triggers", s.pgListTriggers)
	mux.HandleFunc("POST /api/agents/{key}/triggers", s.pgCreateTrigger)
	mux.HandleFunc("PATCH /api/triggers/{id}", s.pgUpdateTrigger)
	mux.HandleFunc("DELETE /api/triggers/{id}", s.pgDeleteTrigger)
	mux.HandleFunc("GET /api/agents/{key}/prompts", s.pgListPromptVersions)
	mux.HandleFunc("GET /api/agents/{key}/variables", s.pgPromptVars)
	mux.HandleFunc("POST /api/agents/{key}/prompt/preview", s.pgPreviewPrompt)
	mux.HandleFunc("GET /api/agents/{key}/visibility", s.pgGetAgentVisibility)
	mux.HandleFunc("PUT /api/agents/{key}/visibility", s.pgSetAgentVisibility)
	// 内置工具目录（描述/参数默认值可改、按 agent 绑定；key 与 handler 在代码层）
	mux.HandleFunc("GET /api/tools", s.pgListTools)
	mux.HandleFunc("PUT /api/tools/{key}", s.pgUpdateTool)
	mux.HandleFunc("POST /api/tools/custom", s.pgCreateCustomTool)
	mux.HandleFunc("POST /api/tools/custom/test", s.pgTestCustomTool)
	mux.HandleFunc("PUT /api/tools/custom/{key}", s.pgUpdateCustomTool)
	mux.HandleFunc("DELETE /api/tools/custom/{key}", s.pgDeleteCustomTool)
	mux.HandleFunc("POST /api/settings/python/detect", s.pgDetectPython)
	mux.HandleFunc("POST /api/tools/{key}/reset", s.pgResetTool)
	// MCP CRUD
	mux.HandleFunc("GET /api/mcp", s.pgListMCP)
	mux.HandleFunc("POST /api/mcp", s.pgSaveMCP)
	mux.HandleFunc("DELETE /api/mcp/{id}", s.pgDeleteMCP)
	mux.HandleFunc("GET /api/mcp/{id}/tools", s.pgMCPTools)
	// MCP 服务端(BEHEMOTH 对外暴露的 /mcp)：开关、访问令牌、调用审计
	mux.HandleFunc("GET /api/mcp-server/settings", s.getMCPServerSettings)
	mux.HandleFunc("PUT /api/mcp-server/settings", s.putMCPServerSettings)
	mux.HandleFunc("GET /api/mcp-server/tokens", s.listMCPServerTokens)
	mux.HandleFunc("POST /api/mcp-server/tokens", s.createMCPServerToken)
	mux.HandleFunc("POST /api/mcp-server/tokens/{id}/revoke", s.revokeMCPServerToken)
	mux.HandleFunc("DELETE /api/mcp-server/tokens/{id}", s.deleteMCPServerToken)
	mux.HandleFunc("GET /api/mcp-server/audit", s.listMCPServerAudit)
	mux.HandleFunc("POST /api/mcp/{id}/refresh", s.pgRefreshMCP)
	// 资产同步 — ScopeSentry 数据源
	mux.HandleFunc("GET /api/sync/scopesentry/status", s.syncSSStatus)
	mux.HandleFunc("POST /api/sync/scopesentry/datasource", s.syncSSDatasource)
	mux.HandleFunc("GET /api/sync/scopesentry/projects", s.syncSSProjects)
	mux.HandleFunc("GET /api/sync/scopesentry/tasks", s.syncSSTasks)
	mux.HandleFunc("POST /api/sync/scopesentry/sync", s.syncSSRun)
	// Skill CRUD (文件系统)
	mux.HandleFunc("GET /api/skills", s.fsListSkills)
	mux.HandleFunc("POST /api/skills", s.fsCreateSkill)
	mux.HandleFunc("POST /api/skills/upload", s.fsUploadSkill)
	mux.HandleFunc("DELETE /api/skills/{name}", s.fsDeleteSkill)
	mux.HandleFunc("GET /api/skills/missing", s.fsMissingSkills)         // 未命中(想调但不存在)的 skill 名
	mux.HandleFunc("DELETE /api/skills/missing", s.fsClearMissingSkills) // 清除已处理/历史未命中 skill 记录
	mux.HandleFunc("GET /api/skills/{name}/usage", s.fsSkillUsage)       // 单个 skill 的最近调用
	mux.HandleFunc("PUT /api/skills/{name}/meta", s.fsUpdateSkillMeta)
	mux.HandleFunc("POST /api/skills/{name}/dirs", s.fsCreateDir)
	mux.HandleFunc("GET /api/skills/{name}/files", s.fsListFiles)
	// {file...} captures path segments including slashes (e.g. scripts/extract.py)
	mux.HandleFunc("GET /api/skills/{name}/files/{file...}", s.fsReadFile)
	mux.HandleFunc("PUT /api/skills/{name}/files/{file...}", s.fsWriteFile)
	mux.HandleFunc("DELETE /api/skills/{name}/files/{file...}", s.fsDeletePath)
	// MCP 资源侧可见性（更具体的 skill 路由会优先匹配）
	mux.HandleFunc("GET /api/visibility/{kind}/{id}", s.pgResourceVisibility)
	mux.HandleFunc("POST /api/visibility/toggle", s.pgToggleVisibility)
	// Skill 可见性（按名称，更具体，优先于上面的通配路由）
	mux.HandleFunc("GET /api/visibility/skill/{name}", s.pgSkillVisibility)
	mux.HandleFunc("POST /api/visibility/skill/toggle", s.pgToggleSkillVisibility)
	// LLM 多 profile
	mux.HandleFunc("GET /api/llm/profiles", s.pgListProfiles)
	mux.HandleFunc("POST /api/llm/profiles", s.pgSaveProfile)
	mux.HandleFunc("DELETE /api/llm/profiles/{id}", s.pgDeleteProfile)
	mux.HandleFunc("POST /api/llm/profiles/active", s.pgActivateProfile)
	s.registerColabG4Routes(mux)
	mux.HandleFunc("GET /api/llm/retry-policy", s.pgGetLLMRetryPolicy)
	mux.HandleFunc("POST /api/llm/retry-policy", s.pgSaveLLMRetryPolicy)
	mux.HandleFunc("GET /api/llm/pool", s.pgLLMPoolStatus)
	mux.HandleFunc("POST /api/llm/pool/reset", s.pgLLMPoolReset)
	mux.HandleFunc("POST /api/llm/models", s.pgListModels)

	// 拦截规则管理
	mux.HandleFunc("GET /api/intercept/rules", s.interceptListRules)
	mux.HandleFunc("POST /api/intercept/rules", s.interceptCreateRule)
	mux.HandleFunc("PUT /api/intercept/rules/{id}", s.interceptUpdateRule)
	mux.HandleFunc("DELETE /api/intercept/rules/{id}", s.interceptDeleteRule)
	mux.HandleFunc("POST /api/intercept/rules/{id}/toggle", s.interceptToggleRule)

	// 资产拦截规则管理（全局黑名单：域名/IP/URL/CIDR）
	mux.HandleFunc("GET /api/asset-intercept/rules", s.assetInterceptListRules)
	mux.HandleFunc("POST /api/asset-intercept/rules", s.assetInterceptCreateRule)
	mux.HandleFunc("PUT /api/asset-intercept/rules/{id}", s.assetInterceptUpdateRule)
	mux.HandleFunc("DELETE /api/asset-intercept/rules/{id}", s.assetInterceptDeleteRule)
	mux.HandleFunc("POST /api/asset-intercept/rules/{id}/toggle", s.assetInterceptToggleRule)

	mux.HandleFunc("GET /api/intercept/pending", s.interceptListPending)
	mux.HandleFunc("GET /api/intercept/pending/{id}", s.interceptGetOne)
	mux.HandleFunc("POST /api/intercept/pending/{id}/decide", s.interceptDecide)
	mux.HandleFunc("GET /api/intercept/history", s.interceptHistory)
	mux.HandleFunc("GET /api/intercept/history/{id}", s.interceptDetail)
	mux.HandleFunc("GET /api/intercept/history/{id}/execution", s.interceptExecution)
	mux.HandleFunc("GET /api/intercept/task/{taskID}", s.interceptListTaskItems)
	mux.HandleFunc("GET /api/intercept/tool-config", s.interceptGetToolConfig)
	mux.HandleFunc("PUT /api/intercept/tool-config", s.interceptSetToolConfig)
	mux.HandleFunc("GET /api/intercept/judge", s.interceptGetJudgeConfig)
	mux.HandleFunc("PUT /api/intercept/judge", s.interceptSetJudgeConfig)
	mux.HandleFunc("GET /api/intercept/judge/usage", s.interceptJudgeUsage) // 兜底审批累计 token 用量

	// Security API endpoints (IOC, anti-bot, backdoor detection)
	mux.HandleFunc("GET /api/v2/security/stats", s.handleSecurityStats)
	mux.HandleFunc("GET /api/v2/security/iocs", s.handleListIOCs)
	mux.HandleFunc("POST /api/v2/security/iocs", s.handleAddIOC)
	mux.HandleFunc("DELETE /api/v2/security/iocs/{ip}", s.handleRemoveIOC)
	mux.HandleFunc("POST /api/v2/security/check", s.handleSecurityCheck)
	mux.HandleFunc("GET /api/v2/security/stealth/config", s.handleGetStealthConfig)
	mux.HandleFunc("PUT /api/v2/security/stealth/config", s.handleUpdateStealthConfig)
	mux.HandleFunc("POST /api/v2/security/stealth/config", s.handleUpdateStealthConfig)

	// Multi-Engine Web Search API (Pentagi-inspired)
	mux.HandleFunc("GET /api/v2/search/engines", s.handleSearchEngines)
	mux.HandleFunc("POST /api/v2/search", s.handleSearch)
	mux.HandleFunc("POST /api/v2/search/exploit", s.handleSearchExploit)
	mux.HandleFunc("POST /api/v2/search/config", s.handleSearchConfig)

	// 2Captcha & CAPTCHA Solver API
	mux.HandleFunc("GET /api/v2/captcha/status", s.handleCaptchaStatus)
	mux.HandleFunc("POST /api/v2/captcha/config", s.handleCaptchaConfig)
	mux.HandleFunc("POST /api/v2/captcha/test", s.handleCaptchaTest)

	// Bug Bounty Finder & Tracker API
	mux.HandleFunc("GET /api/bounties/programs", s.handleListBountyPrograms)
	mux.HandleFunc("POST /api/bounties/programs", s.handleCreateBountyProgram)
	mux.HandleFunc("POST /api/bounties/programs/{id}/hunt", s.handleStartBountyHunt)
	mux.HandleFunc("PATCH /api/bounties/programs/{id}", s.handleUpdateBountyProgram)
	mux.HandleFunc("DELETE /api/bounties/programs/{id}", s.handleDeleteBountyProgram)
	mux.HandleFunc("GET /api/bounties/scanner", s.handleGetBountyScanner)
	mux.HandleFunc("PUT /api/bounties/scanner", s.handlePutBountyScanner)
	mux.HandleFunc("POST /api/bounties/scanner/run", s.handleRunBountyScannerNow)

	// Browser Automation API (Pentagi-inspired)
	mux.HandleFunc("POST /api/v2/browser/screenshot", s.handleBrowserScreenshot)
	mux.HandleFunc("POST /api/v2/browser/content", s.handleBrowserContent)
	mux.HandleFunc("GET /api/v2/browser/config", s.handleGetBrowserConfig)
	mux.HandleFunc("POST /api/v2/browser/config", s.handleBrowserConfig)

	// Patch Monitor & Offensive Security API
	mux.HandleFunc("GET /api/patch-monitor/sources", s.handlePatchMonitorSources)
	mux.HandleFunc("POST /api/patch-monitor/sources", s.handlePatchMonitorAddSource)
	mux.HandleFunc("GET /api/patch-monitor/vulns", s.handlePatchMonitorVulns)
	mux.HandleFunc("GET /api/patch-monitor/exploits", s.handlePatchMonitorExploits)
	mux.HandleFunc("GET /api/patch-monitor/targets", s.handlePatchMonitorTargets)
	mux.HandleFunc("POST /api/patch-monitor/targets", s.handlePatchMonitorAddTarget)
	mux.HandleFunc("POST /api/patch-monitor/targets/auto-match", s.handlePatchMonitorAutoMatchTargets)
	mux.HandleFunc("DELETE /api/patch-monitor/targets/{id}", s.handlePatchMonitorDeleteTarget)
	mux.HandleFunc("POST /api/patch-monitor/start", s.handlePatchMonitorStart)
	mux.HandleFunc("POST /api/patch-monitor/stop", s.handlePatchMonitorStop)
	mux.HandleFunc("POST /api/patch-monitor/check-now", s.handlePatchMonitorCheckNow)
	mux.HandleFunc("GET /api/patch-monitor/status", s.handlePatchMonitorStatus)
	mux.HandleFunc("POST /api/patch-monitor/exploits/generate", s.handlePatchMonitorGenerateExploit)
	mux.HandleFunc("POST /api/payloads/generate", s.handleGeneratePayload)
	mux.HandleFunc("GET /api/research/ios-exploits", s.handleIOSExploits)

	// /api/* goes through Security -> CORS + JWT; everything else is served by the embedded
	// frontend (no JWT required; the optional Basic Auth gate wraps both). With the
	// no-embed build the webui handler just 404s (run `next dev` separately).
	api := gzipAPI(cors(s.requireAuth(s.securityMiddleware(mux))))
	root := http.NewServeMux()
	root.Handle("/api/", api)
	root.Handle("/", s.webuiHandler())
	// /mcp sits outside the Basic Auth gate on purpose: an external MCP client has
	// one Authorization header and it carries the access token, so it could never
	// satisfy both. The endpoint authenticates with access tokens only.
	top := http.NewServeMux()
	top.HandleFunc(mcpEndpointPath, s.serveMCP)
	top.Handle("/", s.requireBasicAuth(root))
	return top
}

// --- handlers ---

// health requires the optional Basic Auth gate but no admin JWT.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// version is protected by the normal JWT middleware and optional Basic Auth gate.
func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"version": BuildVersion})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	out["engine_mode"] = "idle"              // spec enum; overridden below when a task is active
	out["llm_configured"] = s.engine.Ready() // is an LLM provider installed at all
	if tr := s.m.Traffic(); tr != nil {
		c, _ := tr.Count()
		out["traffic"] = c
		out["traffic_enabled"] = true
	}
	if counts, err := s.m.Assets().CountsByType(); err == nil {
		total := 0
		for _, n := range counts {
			total += n
		}
		out["assets"] = total
		out["asset_counts"] = counts
	}

	// resolve the task: explicit ?task=<id> binds to that task (so a detail view
	// never silently follows a globally-changed active task); empty = active.
	taskParam := r.URL.Query().Get("task")
	t := s.m.ResolveTask(taskParam)
	if t == nil {
		if taskParam != "" && taskParam != "active" {
			writeErr(w, 404, "task not found")
			return
		}
		writeJSON(w, 200, out) // no task selected: only global fields
		return
	}
	out["llm_configured"] = s.engine.ReadyFor(t)

	st, _ := t.Store.Stats()
	out["exploration"] = st

	// per-task running state + heartbeat (distinct from "LLM configured").
	intents, _ := t.Store.ListByKind(db.KindIntent, 100000)
	inFlight := 0
	for _, in := range intents {
		if in.State == "running" {
			inFlight++
		}
	}
	goals, _ := t.Store.ListByKind(db.KindGoal, 10000)
	goalsMet := 0
	for _, g := range goals {
		if g.State == "met" {
			goalsMet++
		}
	}
	last := s.engine.LastActivity(t.ID)
	paused := s.engine.IsPaused(t.ID)
	activeCalls := s.engine.ActiveLLMCalls(t.ID)
	running := s.engine.ReadyFor(t) && s.engine.Started(t.ID) && !paused
	// A live event-driven engine with no work is healthy idle. Only a persisted
	// running intent without any corresponding LLM call can be considered stalled.
	stalled := running && activeCalls == 0 && inFlight > 0 && last > 0 && time.Now().Unix()-last > 120

	// engine_mode follows the spec enum (exploring|paused|stalled|idle).
	engineMode := "idle"
	switch {
	case paused:
		engineMode = "paused"
	case stalled:
		engineMode = "stalled"
	case running && activeCalls > 0:
		engineMode = "exploring"
	}
	out["engine_mode"] = engineMode

	out["active_task"] = map[string]any{
		"id": t.ID, "description": t.Description, "goal": t.Goal,
		"running":       running,
		"paused":        paused,
		"engine_mode":   engineMode,
		"in_flight":     inFlight,
		"llm_in_flight": activeCalls,
		"last_activity": last,
		"stalled":       stalled,
		"goals_total":   len(goals),
		"goals_met":     goalsMet,
	}
	writeJSON(w, 200, out)
}

func (s *Server) listTasks(w http.ResponseWriter, r *http.Request) {
	active := ""
	if t := s.m.ActiveTask(); t != nil {
		active = t.ID
	}
	list := s.m.List()
	metrics, _ := s.m.PG().TaskListMetricsAll()
	distinct, _ := s.m.pg.DistinctFindingStatsByTask()
	archiveBlockers, _ := s.m.PG().TaskArchiveBlockers()
	dtos := make([]TaskDTO, 0, len(list))
	for _, t := range list {
		dto := taskDTO(t, s.resolvedTaskStatus(t))
		applyTaskArchiveBlocker(&dto, archiveBlockers)
		metric := metrics[t.ExpID]
		dto.Tokens = tokenTotalDTO(metric.Tokens)
		// prefer the live in-memory heartbeat (fresher) and fall back to the
		// persisted max activity time (survives restarts) for activity display.
		dto.LastActivity = metric.LastActivity
		if live := s.engine.LastActivity(t.ID); live > dto.LastActivity {
			dto.LastActivity = live
		}
		dto.GoalsTotal = metric.Goals.Total
		dto.GoalsMet = metric.Goals.Met
		dto.InFlight = metric.RunningIntents
		dto.DistinctFindings = distinct[t.ID]
		dto.Findings = FindingSeverityDTO{
			Critical: metric.Findings.Critical,
			High:     metric.Findings.High,
			Medium:   metric.Findings.Medium,
			Low:      metric.Findings.Low,
		}
		dtos = append(dtos, dto)
	}
	writeJSON(w, 200, map[string]any{"tasks": dtos, "active": active})
}

func (s *Server) resolvedTaskStatus(t *Task) string {
	if t == nil {
		return "created"
	}
	lifecycle := t.lifecycleSnapshot()
	return s.resolvedTaskStatusFromSnapshot(t, lifecycle)
}

func (s *Server) resolvedTaskStatusFromSnapshot(t *Task, lifecycle taskLifecycleState) string {
	switch {
	case isTerminalStatus(lifecycle.Status):
		return lifecycle.Status
	case lifecycle.Queued:
		return "queued"
	case lifecycle.Paused || s.engine.IsPaused(t.ID):
		return "paused"
	case t.llmStateSnapshot().FailoverState == "chain_exhausted" && s.engine.Started(t.ID):
		// LLM readiness is an execution dependency, not lifecycle state. Keeping
		// an exhausted task running lets the user edit/reset its chain directly.
		return "running"
	case s.engine.ReadyFor(t) && s.engine.Started(t.ID):
		return "running"
	default:
		return "created"
	}
}

func (s *Server) setActive(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !s.m.SetActive(req.ID) {
		writeErr(w, 404, "task not found")
		return
	}
	// resume the engine for the opened task (idempotent — no-op if already running).
	// 排队中的任务:仅设为活跃可查看,不启动引擎(维持并发上限,由 reconcile 补位)。
	if t, ok := s.m.Task(req.ID); ok && !t.lifecycleSnapshot().Queued {
		s.engine.Run(s.ctx, t)
	}
	writeJSON(w, 200, map[string]any{"active": req.ID})
}

// control pauses/resumes a task's autonomous execution (planner + workers).
func (s *Server) control(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Action != "pause" && req.Action != "resume" {
		writeErr(w, 400, "action must be pause|resume")
		return
	}
	result, err := s.applyTaskControl(t, req.Action)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

// controlIntent pauses, resumes, or cancels one local worker intent. A running
// worker is always stopped before state mutation/cleanup, preventing tool output
// that arrives after the user action from recreating deleted blackboard records.
func (s *Server) controlIntent(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除，无法控制意图")
		return
	}
	defer s.engine.decInflight(t.ID)

	iid, err := strconv.ParseInt(r.PathValue("iid"), 10, 64)
	if err != nil || iid <= 0 {
		writeErr(w, 400, "bad intent id")
		return
	}
	var req struct {
		Action string `json:"action"`
		Reason string `json:"reason"` // cancel(删除)时必填:删除原因
		Mode   string `json:"mode"`   // cancel 专用:soft(默认,假删除)| hard(真删除,级联移除独占子孙)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if req.Action != "pause" && req.Action != "resume" && req.Action != "cancel" {
		writeErr(w, 400, "action must be pause|resume|cancel")
		return
	}

	result, err := s.applyIntentControl(r.Context(), t, iid, req.Action, req.Reason, req.Mode)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

// rerunIntent 重跑一条没跑成功的意图(blocked/exhausted/stopped):把它置回 open,worker
// 会重新认领、从头再跑(已写回图谱的 fact/finding/asset 保留);若任务已终态/暂停则顺带复活。
// 用于「出错的 work 点击继续运行」——网络/LLM 抖动导致 blocked 后可一键重试。
func restoreRerunIntent(t *Task, before *db.Node) error {
	if t == nil || before == nil {
		return fmt.Errorf("missing intent rollback snapshot")
	}
	if before.State == "blocked" && before.BlockedReason != "" {
		return t.Store.SetIntentBlockedReason(before.ID, before.BlockedReason)
	}
	return t.Store.SetIntentState(before.ID, before.State)
}

func (s *Server) rerunIntent(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	iid, err := strconv.ParseInt(r.PathValue("iid"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad intent id")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除，无法重跑意图")
		return
	}
	defer s.engine.decInflight(t.ID)
	before, err := t.Store.GetNode(iid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	reopened, err := t.Store.ReopenIntent(iid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !reopened {
		writeErr(w, 409, "该意图不是可重跑状态(仅 blocked/exhausted/stopped 可重跑)")
		return
	}
	queued, err := s.admitTask(t, "resume")
	if err != nil {
		if rollbackErr := restoreRerunIntent(t, before); rollbackErr != nil {
			err = fmt.Errorf("%w; restore intent %d after admission failure: %v", err, iid, rollbackErr)
		}
		writeErr(w, 500, err.Error())
		return
	}
	log.Printf("[task] #%s 意图 #%d 已重开(重跑)", t.ID, iid)
	writeJSON(w, 200, map[string]any{"id": t.ID, "reopened": iid, "queued": queued})
}

// rerunBlocked 批量重跑本任务全部 blocked 意图(适合一次网络/LLM 断连导致多条 blocked 后
// 一键全部重试),置回 open 并复活任务;返回重开的条数。
func (s *Server) rerunBlocked(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除，无法重跑意图")
		return
	}
	defer s.engine.decInflight(t.ID)
	intents, err := t.Store.ListByKind(db.KindIntent, 1000000)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	before := make([]*db.Node, 0)
	for _, intent := range intents {
		if intent.State == "blocked" {
			copy := *intent
			before = append(before, &copy)
		}
	}
	n, err := t.Store.ReopenBlockedIntents()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	queued := false
	if n > 0 {
		queued, err = s.admitTask(t, "resume")
		if err != nil {
			rollbackErrors := make([]string, 0)
			for _, intent := range before {
				if rollbackErr := restoreRerunIntent(t, intent); rollbackErr != nil {
					rollbackErrors = append(rollbackErrors, fmt.Sprintf("intent %d: %v", intent.ID, rollbackErr))
				}
			}
			if len(rollbackErrors) > 0 {
				err = fmt.Errorf("%w; restore blocked intents after admission failure: %s", err, strings.Join(rollbackErrors, "; "))
			}
			writeErr(w, 500, err.Error())
			return
		}
		log.Printf("[task] #%s 批量重开 %d 条 blocked 意图", t.ID, n)
	}
	writeJSON(w, 200, map[string]any{"id": t.ID, "reopened": n, "queued": queued})
}

// getLLM returns the current LLM config (key never exposed).
func (s *Server) getLLM(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"configured":       s.llmOn,
		"provider":         s.llmCfg.Provider(),
		"model":            s.llmCfg.Model,
		"base_url":         s.llmCfg.BaseURL,
		"proxy":            s.llmCfg.Proxy,
		"key_set":          s.llmCfg.APIKey != "",
		"rate_per_second":  s.llmCfg.RatePerSecond,
		"rate_per_minute":  s.llmCfg.RatePerMinute,
		"context_window_k": s.llmCfg.ContextWindowK,
		"thinking_type":    s.llmCfg.ThinkingType,
		"reasoning_effort": s.llmCfg.ReasoningEffort,
	})
}

// setLLM configures the LLM at runtime. A blank api_key keeps the existing key.
func (s *Server) setLLM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider        string  `json:"provider"`
		Model           string  `json:"model"`
		BaseURL         string  `json:"base_url"`
		Proxy           string  `json:"proxy"`
		APIKey          string  `json:"api_key"`
		RatePerSecond   float64 `json:"rate_per_second"`
		RatePerMinute   float64 `json:"rate_per_minute"`
		ContextWindowK  int     `json:"context_window_k"`
		ThinkingType    string  `json:"thinking_type"`
		ReasoningEffort string  `json:"reasoning_effort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfg := agent.ConfigFrom(req.Provider, req.Model, req.BaseURL, req.APIKey, req.Proxy)
	cfg.RatePerSecond, cfg.RatePerMinute = req.RatePerSecond, req.RatePerMinute
	cfg.ThinkingType = req.ThinkingType
	cfg.ReasoningEffort = req.ReasoningEffort
	if k := req.ContextWindowK; k > 0 { // 0 = keep default (200K); cap at 1M
		if k > 1000 {
			k = 1000
		}
		cfg.ContextWindowK = k
	}
	if cfg.APIKey == "" {
		s.cfgMu.Lock()
		cfg.APIKey = s.llmCfg.APIKey // keep existing key if not re-entered
		s.cfgMu.Unlock()
	}
	if cfg.APIKey == "" {
		writeErr(w, 400, "api_key required")
		return
	}
	// Validate provider construction before persisting it as the active profile.
	if _, err := cfg.NewProvider(); err != nil {
		writeErr(w, 400, "provider init failed: "+err.Error())
		return
	}
	if err := s.saveLLMConfig(cfg); err != nil {
		writeErr(w, 500, "persist provider failed: "+err.Error())
		return
	}
	s.invalidateProfileAgents()
	if _, ok := s.loadLLMConfig(); !ok {
		writeErr(w, 500, "saved provider is unavailable")
		return
	}
	if err := s.applyLLM(cfg); err != nil {
		writeErr(w, 400, "provider init failed: "+err.Error())
		return
	}
	log.Printf("[engine] LLM configured via UI: %s / %s", cfg.Provider(), cfg.Model)
	s.getLLM(w, r)
}

// testLLM makes a real minimal completion to verify the config works.
func (s *Server) testLLM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider         string `json:"provider"`
		Model            string `json:"model"`
		BaseURL          string `json:"base_url"`
		Proxy            string `json:"proxy"`
		APIKey           string `json:"api_key"`
		ThinkingType     string `json:"thinking_type"`
		ReasoningEffort  string `json:"reasoning_effort"`
		ProfileID        *int64 `json:"profile_id"`         // 测已存 profile 时传入：api_key 为空则用它存的 key
		Streaming        *bool  `json:"streaming"`          // 省略=流式，与保存 profile 时同一套默认
		SessionHeaderKey string `json:"session_header_key"` // 非空=测试时也带该自定义会话头，值为一次性随机 session id
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(req.Provider) == "jev" {
		apiKey := strings.TrimSpace(req.APIKey)
		baseURL, model := strings.TrimSpace(req.BaseURL), strings.TrimSpace(req.Model)
		if req.ProfileID != nil {
			if p, err := s.m.pg.ProfileByID(*req.ProfileID); err == nil && p != nil {
				if apiKey == "" {
					apiKey = p.APIKey
				}
				if baseURL == "" {
					baseURL = p.BaseURL
				}
				if model == "" {
					model = p.Model
				}
			}
		}
		if apiKey == "" {
			writeJSON(w, 200, map[string]any{"ok": false, "error": "未提供 API Key"})
			return
		}
		if model == "" {
			model = jev.DefaultModel
		}
		proxy := strings.TrimSpace(req.Proxy)
		if proxy == "" && req.ProfileID != nil {
			if p, err := s.m.pg.ProfileByID(*req.ProfileID); err == nil && p != nil {
				proxy = p.Proxy
			}
		}
		testCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		lat, reply, err := (jev.Config{BaseURL: baseURL, APIKey: apiKey, Model: model, Proxy: proxy}).TestConnection(testCtx)
		if err != nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "latency_ms": lat.Milliseconds(), "model": model, "reply": truncateReply(reply)})
		return
	}
	cfg := agent.ConfigFrom(req.Provider, req.Model, req.BaseURL, req.APIKey, req.Proxy)
	// mirror production: send the SAME thinking params so a provider that rejects the
	// reasoning_effort/thinking field fails the test too (no false "test ok, run 400").
	cfg.ThinkingType = req.ThinkingType
	cfg.ReasoningEffort = req.ReasoningEffort
	// 同理，收发模式也照该 profile 的选择来：只支持其中一种通道的端点必须在这里就
	// 暴露，而不是等会话里才发现"测试通过的配置根本跑不动"。
	if req.Streaming != nil {
		cfg.Stream = *req.Streaming
	}
	// 自定义会话头名照该配置来：非空则测试请求也发这个头(值为一次性随机 session id，
	// 见 TestConnection)。opencode zen 等强制要求 x-opencode-session 的端点，缺了它
	// 直接 400，必须在测试路径上也带上，否则"对话通、测试 400"。
	cfg.SessionHeaderKey = req.SessionHeaderKey
	// API Key 解析优先级：表单输入 > 指定 profile 存的 key > 全局配置的 key。
	// 已存 profile 的 key 不回传浏览器，所以测试已存配置时表单为空，需从 DB 取。
	// 会话头名同理：表单未带时用已存 profile 的值兜底。
	if req.ProfileID != nil && (cfg.APIKey == "" || cfg.SessionHeaderKey == "") {
		if p, err := s.m.pg.ProfileByID(*req.ProfileID); err == nil && p != nil {
			if cfg.APIKey == "" {
				cfg.APIKey = p.APIKey
			}
			if cfg.SessionHeaderKey == "" {
				cfg.SessionHeaderKey = p.SessionHeaderKey
			}
		}
	}
	if cfg.APIKey == "" {
		s.cfgMu.Lock()
		cfg.APIKey = s.llmCfg.APIKey
		s.cfgMu.Unlock()
	}
	if cfg.APIKey == "" && isLocalLLMEndpoint(cfg.BaseURL) {
		cfg.APIKey = "ollama"
	}
	if cfg.APIKey == "" {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "API Key is required"})
		return
	}
	// 重试参数【不】带进连接测试:测试有 30s 硬超时,把配置的重试次数/长间隔叠上去
	// 只会让一个本来能用的端点测成"超时失败"。测试看的是"这个端点通不通",重试节奏
	// 是跑起来之后的事。
	lat, reply, err := agent.TestConnection(r.Context(), cfg)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	// 回传模型实际回复，让"测试通过"有据可查：看得见它确实说了话，而不只是 HTTP 200。
	writeJSON(w, 200, map[string]any{
		"ok": true, "latency_ms": lat.Milliseconds(), "model": cfg.Model, "reply": truncateReply(reply),
	})
}

// truncateReply clips a connection-test reply for display. A model told to answer
// "OK" can still ramble (or think out loud); the UI only needs enough to show it
// really said something. Rune-based so multibyte text never splits mid-character.
func truncateReply(s string) string {
	const max = 200
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

type createTaskReq struct {
	Schedule             *scheduleRequest `json:"schedule,omitempty"`
	Name                 string           `json:"name,omitempty"` // 可选任务名称;省略/空=未命名
	CategoryID           *int64           `json:"category_id,omitempty"`
	Description          string           `json:"description"`
	Goal                 string           `json:"goal"`
	LLMProfileID         *int64           `json:"llm_profile_id,omitempty"`  // 指定运行本任务的 LLM 配置;省略/null=用激活配置
	LLMProfileIDs        []int64          `json:"llm_profile_ids,omitempty"` // 有序任务级配置链;第一项初始生效
	SourceTaskIDs        []string         `json:"source_task_ids,omitempty"` // 仅直接、只读继承的来源任务
	CompanyIDs           []int64          `json:"company_ids,omitempty"`     // 关联企业范围并快照关联当前企业资产;不复制资产或强制生成意图
	NoResultSeconds      int              `json:"no_result_seconds"`
	NoResultMinFindings  int              `json:"no_result_min_findings"`
	NoResultMinSeverity  string           `json:"no_result_min_severity"`
	TimeoutSeconds       int              `json:"timeout_seconds"`             // 任务级超时(秒);0/省略=不限时
	PlanHeartbeatSeconds int              `json:"plan_heartbeat_seconds"`      // planner 心跳触发间隔(秒);0/省略=默认600(10min);下限=默认=600,低于自动抬到600
	SeedFirstIntent      *bool            `json:"seed_first_intent,omitempty"` // 创建时直接下发一条种子意图(内容=描述+目标),让 worker 免等首轮 planner 直接开跑;省略/null=默认关闭,走标准先规划再执行。显式传 true 才开(CTF 常一 work 解决时可省掉开跑前的 planner 轮)。
	ShareGlobalAssets    bool             `json:"share_global_assets"`
	CoverageEnabled      *bool            `json:"coverage_enabled,omitempty"` // 资产覆盖度功能;省略/null=默认开(true)。false=关闭覆盖度计算/展示/自动累积范围+隐藏 add_task_scope/list_untested_assets。company 关联不受影响。
	Remark               string           `json:"remark,omitempty"`           // 任务备注(最多2000字);空=无
	WorkerCount          int              `json:"worker_count,omitempty"`     // 本任务 Worker 数;0/省略=用全局默认;上限50
	// InterceptRules 任务级资产拦截/允许规则(创建时录入,存 task_intercept_rules,不进全局表)。
	InterceptRules []taskInterceptRuleReq `json:"intercept_rules,omitempty"`
}

// taskCreateError is a rejected task creation: an HTTP-style status plus a
// message that is safe to show to the caller.
type taskCreateError struct {
	Status int
	Msg    string
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	var req createTaskReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	t, cerr := s.createTaskFromRequest(req)
	if cerr != nil {
		writeErr(w, cerr.Status, cerr.Msg)
		return
	}
	writeJSON(w, 201, taskDTO(t, s.resolvedTaskStatus(t)))
}

// createTaskFromRequest validates a creation request, stores the task and
// launches it. It is the single creation path shared by POST /api/tasks and the
// MCP spawn_task tool, so both apply identical validation.
func (s *Server) createTaskFromRequest(req createTaskReq) (*Task, *taskCreateError) {
	if strings.TrimSpace(req.Description) == "" {
		req.Description = "未命名任务"
	}
	if len(req.LLMProfileIDs) == 0 && req.LLMProfileID != nil {
		req.LLMProfileIDs = []int64{*req.LLMProfileID}
	}
	if err := s.validateTaskProfileIDs(req.LLMProfileIDs); err != nil {
		return nil, &taskCreateError{400, err.Error()}
	}
	if err := db.NormalizeNoResultOptions(&db.TaskCreateOptions{NoResultSeconds: req.NoResultSeconds, NoResultMinFindings: req.NoResultMinFindings, NoResultMinSeverity: req.NoResultMinSeverity}); err != nil {
		return nil, &taskCreateError{400, err.Error()}
	}
	if req.TimeoutSeconds < 0 {
		req.TimeoutSeconds = 0
	}
	if len(req.SourceTaskIDs) > db.MaxTaskSourceCount {
		return nil, &taskCreateError{400, fmt.Sprintf("关联任务最多选择 %d 个", db.MaxTaskSourceCount)}
	}
	sourceIDs := make([]int64, 0, len(req.SourceTaskIDs))
	seenSources := map[int64]bool{}
	for _, raw := range req.SourceTaskIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || id <= 0 || seenSources[id] {
			return nil, &taskCreateError{400, "关联任务 id 无效或重复"}
		}
		if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
			return nil, &taskCreateError{400, fmt.Sprintf("关联任务 #%d 不存在", id)}
		}
		seenSources[id] = true
		sourceIDs = append(sourceIDs, id)
	}
	companyIDs, err := db.NormalizeTaskCompanyIDs(req.CompanyIDs)
	if err != nil {
		return nil, &taskCreateError{400, fmt.Sprintf("关联企业无效：最多选择 %d 个有效企业", db.MaxTaskCompanyCount)}
	}
	req.CompanyIDs = companyIDs
	interceptRules, err := buildTaskInterceptRules(req.InterceptRules)
	if err != nil {
		return nil, &taskCreateError{400, "任务级拦截规则无效：" + err.Error()}
	}
	var schedule *db.TaskScheduleInput
	if req.Schedule != nil {
		input := s.scheduleInput(*req.Schedule, nil)
		input.TaskIDs = nil
		if err := db.ValidateTaskScheduleInput(input); err != nil {
			return nil, &taskCreateError{400, err.Error()}
		}
		schedule = &input
	}
	remark, err := normalizeRemark(req.Remark)
	if err != nil {
		return nil, &taskCreateError{400, err.Error()}
	}
	if req.WorkerCount < 0 {
		return nil, &taskCreateError{400, "Worker 运行数量不能为负数"}
	}
	if req.WorkerCount > db.MaxTaskWorkerCount {
		return nil, &taskCreateError{400, fmt.Sprintf("Worker 运行数量最多 %d", db.MaxTaskWorkerCount)}
	}
	t, err := s.m.CreateTaskWithOptions(req.Description, req.Goal, db.TaskCreateOptions{
		Schedule: schedule,
		Name:     strings.TrimSpace(req.Name), CategoryID: req.CategoryID,
		SourceTaskIDs: sourceIDs, CompanyIDs: req.CompanyIDs, LLMProfileIDs: req.LLMProfileIDs,
		NoResultSeconds: req.NoResultSeconds, NoResultMinFindings: req.NoResultMinFindings, NoResultMinSeverity: req.NoResultMinSeverity,
		TimeoutSeconds: req.TimeoutSeconds, PlanHeartbeatSeconds: req.PlanHeartbeatSeconds,
		CoverageEnabled:   req.CoverageEnabled,
		ShareGlobalAssets: req.ShareGlobalAssets,
		Remark:            remark,
		WorkerCount:       req.WorkerCount,
		InterceptRules:    interceptRules,
	})
	if err != nil {
		if errors.Is(err, db.ErrTaskCategoryInvalid) || errors.Is(err, db.ErrTaskCategoryNotFound) {
			return nil, &taskCreateError{400, "任务分类不存在或无效"}
		}
		if errors.Is(err, db.ErrTaskCompanyIDsInvalid) || errors.Is(err, db.ErrTaskCompanyNotFound) {
			return nil, &taskCreateError{400, "关联企业不存在或无效"}
		}
		return nil, &taskCreateError{500, err.Error()}
	}
	log.Printf("[task] 新建任务 #%s «%s» 目标: %s", t.ID, req.Description, req.Goal)
	// 共享的建后流程(seed + 种子意图 + 后台目标分解 + engine.Run),与 spawn_task 复用同一段。
	// launchTask 内部异步,不阻塞 UI —— 目标分解在后台可见地进行。
	if schedule == nil || schedule.StartImmediately {
		s.launchTask(t, req.Description+" "+req.Goal, req.SeedFirstIntent != nil && *req.SeedFirstIntent)
	} else {
		s.engine.Pause(t.ID, agent.AbortPausedBySchedule)
	}
	return t, nil
}

func (s *Server) validateTaskProfileIDs(ids []int64) error {
	seen := map[int64]bool{}
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return fmt.Errorf("LLM 配置 id 无效或重复")
		}
		seen[id] = true
		if p, err := s.m.pg.ProfileByID(id); err == nil && p != nil && p.Format == "jev" {
			return db.ErrJevProfileJudgeOnly
		}
		if _, ok := s.loadProfileConfig(id); !ok {
			return fmt.Errorf("LLM 配置 #%d 不存在或未设置 API Key", id)
		}
	}
	return nil
}

func (s *Server) updateTaskLLMProfiles(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	// 任何生命周期状态(含终态)都可以改链:任务结束后主 Agent 对话仍走这条链,
	// 模型不可用时不换链就等于把已完成任务的交互一起锁死。
	before := t.llmStateSnapshot()
	var req struct {
		LLMProfileIDs      []int64 `json:"llm_profile_ids"`
		ActiveLLMProfileID *int64  `json:"active_llm_profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if err := s.validateTaskProfileIDs(req.LLMProfileIDs); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	active := int64(0)
	if req.ActiveLLMProfileID != nil {
		active = *req.ActiveLLMProfileID
	}
	reopened, err := s.m.ReplaceTaskLLMProfiles(t.ID, req.LLMProfileIDs, active)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// Profile edits affect only subsequent LLM calls. Existing in-flight calls
	// retain their provider. Concurrency reconciliation treats ActiveLLMCalls as a
	// live slot and postpones an unavailable task's pause/queue transition until
	// the call returns; a nudge lets an idle running task resume promptly.
	t.Notify()
	go s.reconcileConcurrency()
	llmState := t.llmStateSnapshot()
	result := map[string]any{
		"id": t.ID, "llm_profile_ids": llmState.ProfileIDs,
		"active_llm_profile_id": llmState.ActiveID,
		"llm_failover_state":    llmState.FailoverState, "reopened_intents": reopened,
	}
	if !sameOptionalID(before.ActiveID, llmState.ActiveID) {
		event := s.emitManualTaskLLMSwitch(t, before.ActiveID, llmState.ActiveID)
		result["switch_event"] = activityDTO(event)
	}
	writeJSON(w, 200, result)
}

var (
	reURL    = regexp.MustCompile(`https?://[^\s'"]+`)
	reIPPort = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?`)
	reDomain = regexp.MustCompile(`\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::(\d{1,5}))?`)
)

// parseTarget extracts a target (scheme, host, port) from free text, supporting
// full URLs, IP[:port] and domain[:port]. ok=false when nothing parseable.
func parseTarget(text string) (scheme, host string, port int, ok bool) {
	text = strings.TrimSpace(text)
	if m := reURL.FindString(text); m != "" {
		if u, err := url.Parse(m); err == nil && u.Hostname() != "" {
			scheme = strings.ToLower(u.Scheme)
			host = strings.ToLower(u.Hostname())
			port = portOr(u.Port(), defaultPort(scheme))
			return scheme, host, port, true
		}
	}
	if m := reIPPort.FindStringSubmatch(text); m != nil {
		host = m[1]
		port = portOr(m[2], 80)
		return schemeForPort(port), host, port, true
	}
	if m := reDomain.FindStringSubmatch(text); m != nil {
		host = strings.ToLower(m[1])
		if m[2] == "" {
			return "https", host, 443, true
		}
		port = portOr(m[2], 443)
		return schemeForPort(port), host, port, true
	}
	return "", "", 0, false
}

func portOr(s string, d int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return d
}
func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}
func schemeForPort(p int) string {
	if p == 443 || p == 8443 {
		return "https"
	}
	return "http"
}

// llmHost returns the host of the configured LLM endpoint (to keep it out of scope).
func (s *Server) llmHost() string {
	s.cfgMu.Lock()
	base := s.llmCfg.BaseURL
	s.cfgMu.Unlock()
	if base == "" {
		return ""
	}
	if u, err := url.Parse(base); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

func (s *Server) seed(t *Task, text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	scheme, host, port, ok := parseTarget(text)
	if !ok {
		log.Printf("[seed] task %s: 未能从 %q 解析出目标 host/IP，不创建站点（请手动配置 scope）", t.ID, text)
		return
	}
	// Never accidentally seed a Bug Bounty hosting platform URL (e.g. bugcrowd.com,
	// hackerone.com) referenced in metadata headers when the task targets a different company.
	if isKnownBountyPlatformHost(host) && (strings.Contains(text, "Program Policy URL:") || strings.Contains(text, "Program Reference:") || strings.HasPrefix(t.Description, "Bug Bounty Hunt")) {
		log.Printf("[seed] task %s: skipping bounty platform metadata host %q during task seed", t.ID, host)
		return
	}
	// P0-1 guard: never treat the configured LLM gateway as a target.
	if gw := s.llmHost(); gw != "" && host == gw {
		log.Printf("[seed] task %s: 目标 %q 是 LLM 网关，拒绝作为渗透目标", t.ID, host)
		return
	}

	u := scheme + "://" + host
	if !(scheme == "https" && port == 443) && !(scheme == "http" && port == 80) {
		u += ":" + strconv.Itoa(port)
	}
	var rootID int64
	if as := s.m.Assets(); as != nil {
		taskID, _ := strconv.ParseInt(t.ID, 10, 64)
		if net.ParseIP(host) != nil {
			rootID, _ = as.UpsertIP(db.UpsertIPReq{IP: host, TaskID: taskID})
		} else if scheme == "https" || scheme == "http" {
			rootID, _ = as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: u, TaskID: taskID})
		} else {
			rootID, _ = as.UpsertRootDomain(db.UpsertRootDomainReq{Domain: host, TaskID: taskID})
		}
		if rootID > 0 {
			_ = as.SetTaskAssetSource(taskID, rootID, "task", "由任务描述或目标初始化", nil)
		}
	}
	// anchor the seeded assets to this task's begin root as lineage/provenance
	// (the asset graph is global and shared; anchoring no longer gates reads).
	if rootID > 0 {
		if begin, _ := t.Store.OriginFactID(); begin > 0 {
			_ = t.Store.Anchor(begin, rootID)
		}
	}
	log.Printf("[seed] task %s: 目标站点 %s", t.ID, u)
	// 不在这里 Notify:首轮是否触发统一由 engine.Run 的 HasActiveIntent 决定(种子意图任务
	// 跳过首轮)。seed 早于 Run 执行,若在此 Notify 会 buffered 到通道、被 plannerLoop 启动时
	// 消费掉而绕过 Run 的门控 → 种子任务仍误触发首轮。
}

// seedFirstIntent writes ONE open intent (summary = 描述+目标) into the task's
// frontier at creation, so a worker can claim and run it immediately without first
// waiting a planner round. Mirrors a planner top-level intent: it links from the
// origin fact (RelDerivedFrom) so it still traces back to a fact node. Best-effort —
// a failure just falls back to the normal planner-driven flow.
func (s *Server) seedFirstIntent(t *Task) {
	summary := fmt.Sprintf("完成任务目标：%s（任务：%s）", t.Goal, t.Description)
	id, err := t.Store.AddIntent(map[string]any{"summary": summary}, 8, nil, "seed")
	if err != nil {
		log.Printf("[seed] task %s: 下发种子意图失败: %v", t.ID, err)
		return
	}
	if origin, _ := t.Store.OriginFactID(); origin > 0 {
		_ = t.Store.Link(origin, db.RelDerivedFrom, id)
	}
	log.Printf("[seed] task %s: 已下发种子意图 #%d", t.ID, id)
}

func (s *Server) getTask(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	dto := taskDTO(t, s.resolvedTaskStatus(t))
	archiveBlockers, _ := s.m.PG().TaskArchiveBlockers()
	applyTaskArchiveBlocker(&dto, archiveBlockers)
	writeJSON(w, 200, dto)
}

// taskCoverage returns a task's rough asset test coverage (denominator/tested/backlog).
func (s *Server) taskCoverage(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	// 资产覆盖度功能关闭 → 短路返回 {enabled:false}，前端据此隐藏覆盖度卡片/进度。
	if !t.CoverageEnabled {
		writeJSON(w, 200, &db.Coverage{Enabled: false, ByType: []db.CoverageByType{}})
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	cov, err := as.TaskCoverageWithSources(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cov.Enabled = true
	writeJSON(w, 200, cov)
}

// taskCoverageGraph returns the force-directed asset coverage graph for a task:
// all in-scope assets (每种类型) + 连接用的根域名/公司节点, each carrying tested/in_scope.
func (s *Server) taskCoverageGraph(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	g, err := as.BuildCoverageGraph(taskID, t.ExpID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, g)
}

// taskAssetRefs returns the intents / facts / findings in this task anchored to a
// given asset id — powers the coverage-graph node drawer's「关联意图 / 关联事实」。
func (s *Server) taskAssetRefs(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	assetID, _ := strconv.ParseInt(r.URL.Query().Get("asset_id"), 10, 64)
	if assetID <= 0 {
		writeErr(w, 400, "需要 asset_id")
		return
	}
	refs, err := t.Store.AssetRefsWithSources(assetID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	intents := []CoverageAssetRefDTO{}
	facts := []CoverageAssetRefDTO{}
	findings := []CoverageAssetRefDTO{}
	for _, ref := range refs {
		dto := coverageAssetRefDTO(ref)
		switch ref.Kind {
		case "intent":
			intents = append(intents, dto)
		case "fact":
			facts = append(facts, dto)
		case "finding":
			findings = append(findings, dto)
		}
	}
	writeJSON(w, 200, map[string]any{"intents": intents, "facts": facts, "findings": findings})
}

// taskScopeList returns a task's scope rows (coverage denominator sources).
func (s *Server) taskScopeList(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	rows, err := as.ListTaskScopeWithSources(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"scope": rows})
}

func (s *Server) taskScopeAdd(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	var body struct {
		Kind   string `json:"kind"`
		Value  string `json:"value"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	ts, err := as.AddAgentScope(taskID, body.Kind, body.Value, body.Reason, "manual")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, ts)
}

func (s *Server) taskScopeDelete(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	scopeID, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid scope id")
		return
	}
	deleted, err := as.DeleteTaskScope(taskID, scopeID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !deleted {
		writeErr(w, 404, "scope row not found")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) frontier(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeJSON(w, 200, []any{})
		return
	}
	fr, _ := t.Store.Frontier(atoiDefault(r.URL.Query().Get("limit"), 100))
	writeJSON(w, 200, taskNodeDTOs(fr))
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	// 无 task 参数 → 全局「发现」页：从独立 findings 表读取（任务删除后 finding 依然保留）。
	// 带 task 参数 → 仅该任务（任务概览/发现 Tab 用），从 exploration_nodes 读（任务在则节点在）。
	q := r.URL.Query()
	taskParam := q.Get("task")
	if taskParam == "" {
		// 带 page/limit → 服务端分页 {items,total,...}；不带 → 裸数组（dashboard 汇总用，
		// 与 intents 端点的兼容策略一致）。筛选/排序统一下推到 SQL。
		if q.Get("page") == "" && q.Get("limit") == "" {
			fs, _ := s.m.pg.ListFindings(500)
			assets := s.resolveFindingAssets(fs)
			out := make([]FindingDTO, 0, len(fs))
			for _, f := range fs {
				out = append(out, findingFromDB(f, assets))
			}
			writeJSON(w, 200, out)
			return
		}
		page := findingPaginationParam(q.Get("page"), 1, 0)
		limit := findingPaginationParam(q.Get("limit"), 20, 200)
		fs, total, err := s.m.pg.ListFindingsPage(findingFilterFromQuery(q), page, limit)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		assets := s.resolveFindingAssets(fs)
		out := make([]FindingDTO, 0, len(fs))
		for _, f := range fs {
			out = append(out, findingFromDB(f, assets))
		}
		writeJSON(w, 200, map[string]any{"items": out, "total": total, "page": page, "page_size": limit})
		return
	}
	t := s.m.ResolveTask(taskParam)
	if t == nil {
		writeJSON(w, 200, []any{})
		return
	}
	f, err := t.Store.ListByKind(db.KindFinding, 200)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	tid, _ := strconv.ParseInt(t.ID, 10, 64)
	meta, err := s.m.pg.FindingMetaByNodeID(tid)
	if err != nil {
		log.Printf("[findings] task=%s meta: %v", t.ID, err)
	}
	var aidSet []int64
	for _, m := range meta {
		aidSet = append(aidSet, m.AssetIDs...)
	}
	assets := s.resolveAssetIDs(aidSet)
	out := findingDTOsForTask(t, f, meta, assets)

	// Related-task findings are a live, read-only view. Provenance metadata lets
	// the task UI suppress mutation affordances while retaining stable ids.
	sources, err := t.Store.DirectSourceStores()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, source := range sources {
		nodes, listErr := source.Store.ListByKind(db.KindFinding, 200)
		if listErr != nil {
			writeErr(w, 500, listErr.Error())
			return
		}
		for _, node := range nodes {
			node.SourceTaskID = source.Task.TaskID
			node.Inherited = true
		}
		sourceMeta, metaErr := s.m.pg.FindingMetaByNodeID(source.Task.TaskID)
		if metaErr != nil {
			log.Printf("[findings] source_task=%d meta: %v", source.Task.TaskID, metaErr)
		}
		var sourceAssetIDs []int64
		for _, item := range sourceMeta {
			sourceAssetIDs = append(sourceAssetIDs, item.AssetIDs...)
		}
		out = append(out, findingDTOsForOwner(
			i64s(source.Task.TaskID),
			source.Task.Description,
			nodes,
			sourceMeta,
			s.resolveAssetIDs(sourceAssetIDs),
		)...)
	}
	writeJSON(w, 200, out)
}

// normFilter maps the frontend's "all" sentinel (and empty) to "" so the DB layer
// treats it as no filter.
func normFilter(v string) string {
	if v == "all" {
		return ""
	}
	return v
}

// resolveFindingAssets loads every asset anchored by the given findings, keyed by
// id, so each finding DTO can render its assets' labels.
func (s *Server) resolveFindingAssets(fs []*db.DBFinding) map[int64]*db.Asset {
	var ids []int64
	for _, f := range fs {
		ids = append(ids, f.AssetIDs...)
	}
	return s.resolveAssetIDs(ids)
}

// resolveAssetIDs de-dupes ids and loads their asset rows into an id→asset map.
func (s *Server) resolveAssetIDs(ids []int64) map[int64]*db.Asset {
	assets := map[int64]*db.Asset{}
	seen := map[int64]bool{}
	var uniq []int64
	for _, id := range ids {
		if id > 0 && !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}
	if len(uniq) == 0 {
		return assets
	}
	list, err := s.m.pg.Assets().GetByIDs(uniq)
	if err != nil {
		log.Printf("[findings] resolve assets: %v", err)
	}
	for _, a := range list {
		assets[a.ID] = a
	}
	return assets
}

// findingStats serves filtered, pagination-independent counts and global options.
func (s *Server) findingStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.m.pg.FilteredFindingStats(findingFilterFromQuery(r.URL.Query()))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, st)
}

// getFinding returns one finding by its standalone-table id (DTO finding_id),
// with anchored assets resolved for display.
func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	assets := s.resolveAssetIDs(f.AssetIDs)
	dto := findingFromDB(f, assets)
	cid, err := s.m.pg.FindingCaseID(f.ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if cid > 0 {
		dto.CaseID = i64s(cid)
	}
	if contextTaskID := strings.TrimSpace(r.URL.Query().Get("context_task")); contextTaskID != "" {
		contextTask := s.m.ResolveTask(contextTaskID)
		if contextTask == nil {
			writeErr(w, 404, "context task not found")
			return
		}
		sourceTaskID, inherited, allowed := findingProvenanceInTask(contextTask, f.TaskID)
		if !allowed {
			writeErr(w, 404, "finding not available in task context")
			return
		}
		dto.SourceTaskID = sourceTaskID
		dto.Inherited = inherited
	}
	writeJSON(w, 200, dto)
}

// findingsExport 导出发现页的漏洞。
//
//	scope   = filtered（沿用页面筛选）| all（全部）| selected（勾选的 ids）
//	format  = md-single（整合一份 .md）| md-zip（一漏洞一 .md,打包 zip）
//	          | csv | json
//	ids     = 逗号分隔的 finding id（scope=selected 时必填）
//	筛选参数 severity/status/vulnclass/task_id/q/sort 与列表接口一致（scope=filtered 用）。
func (s *Server) findingsExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scope := q.Get("scope")
	format := q.Get("format")

	var ids []int64
	var filter db.FindingFilter
	switch scope {
	case "selected":
		for _, part := range strings.Split(q.Get("ids"), ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			id, err := strconv.ParseInt(part, 10, 64)
			if err != nil || id <= 0 {
				writeErr(w, 400, "bad finding id: "+part)
				return
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			writeErr(w, 400, "no findings selected")
			return
		}
	case "all":
		// 空 filter = 不加任何条件。
	case "filtered", "":
		filter = findingFilterFromQuery(q)
	default:
		writeErr(w, 400, "bad scope: "+scope)
		return
	}

	fs, err := s.m.pg.ListFindingsForExport(filter, ids)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	var casePlan *findingCaseExportPlan
	if q.Get("mode") == "consolidated" {
		fs, casePlan, err = s.prepareFindingCaseExport(fs)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	stage, err := os.MkdirTemp("", "behemoth-finding-export-")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer os.RemoveAll(stage)
	if err = s.evidenceStore().StageFindingsExport(r.Context(), fs, stage, format == "md-zip"); err != nil {
		evidenceError(w, err)
		return
	}
	if casePlan != nil {
		fs, err = s.consolidateFindingCaseExport(fs, casePlan, q.Get("include_originals") == "true")
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	now := time.Now()
	stamp := now.Format("20060102-150405")
	setDownload := func(contentType, filename string) {
		w.Header().Set("Content-Type", contentType)
		// Keep an ASCII fallback for older clients and provide the real UTF-8
		// name through RFC 5987. Browsers otherwise commonly decode Chinese
		// names using the platform legacy code page.
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, sanitizeFilename(filename), url.PathEscape(filename)))
	}

	switch format {
	case "md-single":
		setDownload("text/markdown; charset=utf-8", "findings-"+stamp+".md")
		_, _ = w.Write([]byte(report.FindingsMarkdown(fs, now)))
	case "md-zip":
		path := filepath.Join(stage, "findings.zip")
		if err := buildFindingsEvidenceZip(path, fs, stage, now, s.m.dir); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		file, err := os.Open(path)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		defer file.Close()
		setDownload("application/zip", "findings-"+stamp+".zip")
		http.ServeContent(w, r, "findings.zip", now, file)
	case "csv":
		setDownload("text/csv; charset=utf-8", "findings-"+stamp+".csv")
		_, _ = w.Write(report.FindingsCSV(fs))
	case "json":
		assets := s.resolveFindingAssets(fs)
		out := make([]FindingDTO, 0, len(fs))
		for _, f := range fs {
			for i := range f.TrafficBindings {
				f.TrafficBindings[i].Snapshot.ReqHead = ""
				f.TrafficBindings[i].Snapshot.RespHead = ""
			}
			out = append(out, findingFromDB(f, assets))
		}
		setDownload("application/json; charset=utf-8", "findings-"+stamp+".json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	default:
		writeErr(w, 400, "bad format: "+format)
	}
}

func findingProvenanceInTask(contextTask *Task, findingTaskID *int64) (sourceTaskID string, inherited, allowed bool) {
	if contextTask == nil || findingTaskID == nil {
		return "", false, false
	}
	contextID, err := strconv.ParseInt(contextTask.ID, 10, 64)
	if err != nil {
		return "", false, false
	}
	if *findingTaskID == contextID {
		return "", false, true
	}
	for _, sourceID := range contextTask.lifecycleSnapshot().SourceTaskIDs {
		if sourceID == *findingTaskID {
			return i64s(sourceID), true, true
		}
	}
	return "", false, false
}

// findingLineage returns the exploration sub-DAG from the task root to this
// finding's node — or synthesizes an authentic Asset -> PoC Verification -> Finding
// lineage graph when the finding was created standalone in Chat (or after task cleanup).
func (s *Server) findingLineage(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	if f.NodeID != nil && f.TaskID != nil {
		if t := s.m.ResolveTask(i64s(*f.TaskID)); t != nil {
			nodes, edges, lerr := t.Store.FindingLineage(*f.NodeID)
			if lerr != nil {
				writeErr(w, 500, lerr.Error())
				return
			}
			if len(nodes) > 0 {
				writeJSON(w, 200, map[string]any{"nodes": taskNodeDTOs(nodes), "edges": edgeDTOs(edges)})
				return
			}
		}
	}
	nodes, edges := s.buildStandaloneFindingLineage(f)
	writeJSON(w, 200, map[string]any{"nodes": nodes, "edges": edges})
}

func (s *Server) buildStandaloneFindingLineage(f *db.DBFinding) ([]TaskNodeDTO, []EdgeDTO) {
	ts := rfc3339(f.CreatedAt)
	dto := findingFromDB(f, s.resolveFindingAssets([]*db.DBFinding{f}))

	originSummary := "Standalone Security Assessment (Chat Agent)"
	if strings.TrimSpace(f.TaskDescription) != "" {
		originSummary = f.TaskDescription
	}
	originPayload, _ := json.Marshal(map[string]any{
		"summary":     originSummary,
		"description": f.Summary,
	})
	nodes := []TaskNodeDTO{
		{
			ID:       "origin-1",
			Type:     "fact",
			State:    "origin",
			Origin:   "agent",
			Priority: 5,
			Payload:  string(originPayload),
			TS:       ts,
		},
	}
	var edges []EdgeDTO

	var assetNodeIDs []string
	for idx, a := range dto.Assets {
		nid := fmt.Sprintf("asset-%d", idx+1)
		p, _ := json.Marshal(map[string]any{
			"summary":    fmt.Sprintf("[%s] %s", a.Type, a.Label),
			"asset_id":   a.ID,
			"asset_type": a.Type,
			"label":      a.Label,
		})
		nodes = append(nodes, TaskNodeDTO{
			ID:       nid,
			Type:     "fact",
			State:    "confirmed",
			Origin:   "recon",
			Priority: 5,
			Payload:  string(p),
			TS:       ts,
		})
		edges = append(edges, EdgeDTO{Src: "origin-1", Dst: nid, Rel: "spawns"})
		assetNodeIDs = append(assetNodeIDs, nid)
	}

	pocSummary := "Active Vulnerability Probing & PoC Verification"
	if evLine := firstLine(strings.TrimSpace(f.Evidence), 140); evLine != "" {
		pocSummary = evLine
	}
	pocPayload, _ := json.Marshal(map[string]any{
		"summary":  pocSummary,
		"evidence": f.Evidence,
	})
	nodes = append(nodes, TaskNodeDTO{
		ID:       "poc-1",
		Type:     "intent",
		State:    "done",
		Origin:   "auto",
		Priority: 7,
		Payload:  string(pocPayload),
		TS:       ts,
	})
	if len(assetNodeIDs) > 0 {
		for _, aid := range assetNodeIDs {
			edges = append(edges, EdgeDTO{Src: aid, Dst: "poc-1", Rel: "spawns"})
		}
	} else {
		edges = append(edges, EdgeDTO{Src: "origin-1", Dst: "poc-1", Rel: "spawns"})
	}

	prio := 5
	switch strings.ToLower(f.Severity) {
	case "critical":
		prio = 10
	case "high":
		prio = 8
	case "medium":
		prio = 6
	case "low":
		prio = 3
	}
	title := strings.TrimSpace(f.Name)
	if title == "" {
		title = f.VulnClass
	}
	findingPayload, _ := json.Marshal(map[string]any{
		"name":      title,
		"vulnclass": f.VulnClass,
		"severity":  f.Severity,
		"summary":   f.Summary,
		"evidence":  f.Evidence,
	})
	findingNodeID := fmt.Sprintf("finding-%d", f.ID)
	nodes = append(nodes, TaskNodeDTO{
		ID:       findingNodeID,
		Type:     "finding",
		State:    f.Status,
		Origin:   "auto",
		Priority: prio,
		Payload:  string(findingPayload),
		TS:       ts,
	})
	edges = append(edges, EdgeDTO{Src: "poc-1", Dst: findingNodeID, Rel: "yields"})
	return nodes, edges
}

// patchFinding partially updates a finding: any subset of {status, severity}.
// The id is the standalone findings-table id (DTO finding_id). Severity edits are
// mirrored onto the originating exploration node so the per-task view stays in
// sync. Returns the updated finding DTO.
func (s *Server) patchFinding(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var body struct {
		Status    *string `json:"status"`
		Severity  *string `json:"severity"`
		Name      *string `json:"name"`
		VulnClass *string `json:"vulnclass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if body.Status == nil && body.Severity == nil && body.Name == nil && body.VulnClass == nil {
		writeErr(w, 400, "nothing to update: provide status/severity/name/vulnclass")
		return
	}
	if body.Status != nil {
		if !db.ValidFindingStatus(*body.Status) {
			writeErr(w, 400, "bad status: "+*body.Status)
			return
		}
		// 走带通知的版本：状态更新与「状态变更推送事件」在同一事务里落库，
		// 避免出现状态已改而推送事件丢失的窗口。事件登记失败不影响状态更新，
		// 所以只记日志、不向调用方报错。
		from, found, notified, err := s.m.pg.SetFindingStatusWithNotify(r.Context(), id, *body.Status)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if !found {
			writeErr(w, 404, "finding not found")
			return
		}
		if !notified && from != *body.Status {
			log.Printf("[notify] 状态变更事件未登记 finding=%d %s→%s（状态已更新）", id, from, *body.Status)
		}
	}
	if body.Severity != nil {
		if !db.ValidSeverity(*body.Severity) {
			writeErr(w, 400, "bad severity: "+*body.Severity)
			return
		}
		n, err := s.m.pg.SetFindingSeverity(id, *body.Severity)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if n == 0 {
			writeErr(w, 404, "finding not found")
			return
		}
	}
	if body.Name != nil {
		n, err := s.m.pg.SetFindingName(id, strings.TrimSpace(*body.Name))
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if n == 0 {
			writeErr(w, 404, "finding not found")
			return
		}
	}
	if body.VulnClass != nil {
		n, err := s.m.pg.SetFindingVulnClass(id, strings.TrimSpace(*body.VulnClass))
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if n == 0 {
			writeErr(w, 404, "finding not found")
			return
		}
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	writeJSON(w, 200, findingFromDB(f, s.resolveAssetIDs(f.AssetIDs)))
}

// deleteFinding removes a finding (findings row + originating exploration node).
// id is the standalone findings-table id (DTO finding_id).
func (s *Server) deleteFinding(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	n, err := s.m.pg.DeleteFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if n == 0 {
		writeErr(w, 404, "finding not found")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "id": id})
}

func (s *Server) intents(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		// Back-compat: bare list shape when the task can't be resolved.
		writeJSON(w, 200, []any{})
		return
	}
	q := r.URL.Query()
	limit := min(atoiDefault(q.Get("limit"), 300), 500)
	// No paging params → preserve the legacy bare-array response so existing callers
	// (and the poll) keep working unchanged.
	if q.Get("before") == "" && q.Get("page") == "" {
		in, err := t.Store.ListByKind(db.KindIntent, limit)
		if err != nil {
			log.Printf("[intents] task=%s limit=%d: %v", t.ID, limit, err)
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, taskNodeDTOs(in))
		return
	}
	// Paged form: ?before=<id> (or ?page as a marker) → {items, has_more} so the
	// worker session list can reach past the old fixed 300 boundary on scroll. It
	// also includes immutable intent results from directly related tasks; those
	// rows never participate in this task's frontier or claim path.
	before := int64(atoiDefault(q.Get("before"), 0))
	in, hasMore, err := taskIntentHistoryPage(t.Store, before, limit, false, 0)
	if err != nil {
		log.Printf("[intents] task=%s before=%d limit=%d: %v", t.ID, before, limit, err)
		writeErr(w, 500, err.Error())
		return
	}
	sources, err := t.Store.DirectSourceStores()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, source := range sources {
		items, sourceMore, sourceErr := taskIntentHistoryPage(source.Store, before, limit, true, source.Task.TaskID)
		if sourceErr != nil {
			writeErr(w, 500, sourceErr.Error())
			return
		}
		in = append(in, items...)
		hasMore = hasMore || sourceMore
	}
	sort.Slice(in, func(i, j int) bool { return in[i].ID > in[j].ID })
	if len(in) > limit {
		in = in[:limit]
		hasMore = true
	}
	writeJSON(w, 200, map[string]any{"items": taskNodeDTOs(in), "has_more": hasMore})
}

func inheritedIntentResult(state string) bool {
	switch state {
	case "done", "blocked", "exhausted", "stopped":
		return true
	default:
		return false
	}
}

// inheritedGraphSnapshot exposes immutable source-task history without leaking
// work that is still open or running. Edges are filtered with the nodes so the
// response cannot contain dangling ids that reveal hidden live intent topology.
func inheritedGraphSnapshot(nodes []*db.Node, edges []db.Edge, sourceTaskID int64) ([]*db.Node, []db.Edge) {
	visible := make(map[int64]struct{}, len(nodes))
	filteredNodes := make([]*db.Node, 0, len(nodes))
	for _, node := range nodes {
		if node == nil || (node.Kind == db.KindIntent && !inheritedIntentResult(node.State)) {
			continue
		}
		node.SourceTaskID = sourceTaskID
		node.Inherited = true
		visible[node.ID] = struct{}{}
		filteredNodes = append(filteredNodes, node)
	}
	filteredEdges := make([]db.Edge, 0, len(edges))
	for _, edge := range edges {
		if _, ok := visible[edge.From]; !ok {
			continue
		}
		if _, ok := visible[edge.To]; !ok {
			continue
		}
		filteredEdges = append(filteredEdges, edge)
	}
	return filteredNodes, filteredEdges
}

// taskIntentHistoryPage returns one newest-first page for an exploration.
// A source may have many open/running intents, so keep paging until enough
// historical results are collected instead of leaking its frontier into the UI.
func taskIntentHistoryPage(store *db.ExplorationStore, before int64, limit int, inherited bool, sourceTaskID int64) ([]*db.Node, bool, error) {
	if !inherited {
		return store.ListByKindPage(db.KindIntent, before, limit)
	}
	batch := max(limit, 300)
	cursor := before
	out := make([]*db.Node, 0, limit+1)
	for {
		page, more, err := store.ListByKindPage(db.KindIntent, cursor, batch)
		if err != nil {
			return nil, false, err
		}
		for _, node := range page {
			if !inheritedIntentResult(node.State) {
				continue
			}
			node.SourceTaskID = sourceTaskID
			node.Inherited = true
			out = append(out, node)
			if len(out) > limit {
				return out[:limit], true, nil
			}
		}
		if !more || len(page) == 0 {
			return out, false, nil
		}
		cursor = page[len(page)-1].ID
	}
}

// explorationGraph returns the whole exploration chain (task graph) as nodes+edges.
func (s *Server) explorationGraph(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeJSON(w, 200, map[string]any{"nodes": []any{}, "edges": []any{}})
		return
	}
	nodes, err := t.Store.Nodes(2000)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	edges, err := t.Store.Edges(5000)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	sources, err := t.Store.DirectSourceStores()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, source := range sources {
		sourceNodes, nodeErr := source.Store.Nodes(2000)
		if nodeErr != nil {
			writeErr(w, 500, nodeErr.Error())
			return
		}
		sourceEdges, edgeErr := source.Store.Edges(5000)
		if edgeErr != nil {
			writeErr(w, 500, edgeErr.Error())
			return
		}
		sourceNodes, sourceEdges = inheritedGraphSnapshot(sourceNodes, sourceEdges, source.Task.TaskID)
		nodes = append(nodes, sourceNodes...)
		edges = append(edges, sourceEdges...)
	}
	writeJSON(w, 200, map[string]any{"nodes": taskNodeDTOs(nodes), "edges": edgeDTOs(edges)})
}

// explorationNodes serves the 播报板: this task's own exploration nodes as a
// paged time series (newest first unless ?order=asc), filterable by kind/state
// and a payload substring. Inherited nodes are deliberately out of scope — the
// board reports what this task is doing right now, and paging across the source
// tasks' stores would make the cursor meaningless.
// Response also carries the edges touching the page plus the neighbour nodes
// they point at, so each row can state where it came from and what it produced.
func (s *Server) explorationNodes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 1)
	size := atoiDefault(q.Get("size"), 20)
	t := s.m.ResolveTask(q.Get("task"))
	if t == nil {
		writeJSON(w, 200, map[string]any{
			"items": []any{}, "total": 0, "page": page, "size": size,
			"edges": []any{}, "refs": map[string]any{},
		})
		return
	}
	filter := db.NodeFilter{
		Kinds:  csvValues(q.Get("kind")),
		States: csvValues(q.Get("state")),
		Query:  q.Get("q"),
		Asc:    q.Get("order") == "asc",
	}
	nodes, total, err := t.Store.NodesPage(filter, page, size)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ids := make([]int64, 0, len(nodes))
	onPage := make(map[int64]bool, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
		onPage[n.ID] = true
	}
	edges, err := t.Store.EdgesTouching(ids)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	neighbourSet := map[int64]bool{}
	for _, e := range edges {
		if !onPage[e.From] {
			neighbourSet[e.From] = true
		}
		if !onPage[e.To] {
			neighbourSet[e.To] = true
		}
	}
	neighbourIDs := make([]int64, 0, len(neighbourSet))
	for id := range neighbourSet {
		neighbourIDs = append(neighbourIDs, id)
	}
	neighbours, err := t.Store.NodesByIDs(neighbourIDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	refs := make(map[string]TaskNodeDTO, len(neighbours))
	for _, n := range neighbours {
		refs[i64s(n.ID)] = taskNodeDTO(n)
	}
	writeJSON(w, 200, map[string]any{
		"items":  taskNodeDTOs(nodes),
		"total":  total,
		"page":   page,
		"size":   size,
		"edges":  edgeDTOs(edges),
		"refs":   refs,
		"assets": s.nodeAnchoredAssets(t, append(ids, neighbourIDs...)),
	})
}

// nodeAnchoredAssets resolves the exploration_anchors of the given nodes into
// display-ready asset labels, keyed by node id. Anchors are provenance decoration
// for the 播报板 — a failure here must not cost the caller its page, so errors are
// logged and degrade to "no assets".
func (s *Server) nodeAnchoredAssets(t *Task, nodeIDs []int64) map[string][]FindingAssetDTO {
	out := map[string][]FindingAssetDTO{}
	anchors, err := t.Store.NodeAssets(nodeIDs)
	if err != nil {
		log.Printf("[broadcast] node assets: %v", err)
		return out
	}
	var flat []int64
	for _, ids := range anchors {
		flat = append(flat, ids...)
	}
	assets := s.resolveAssetIDs(flat)
	for nodeID, ids := range anchors {
		if dtos := findingAssetDTOs(ids, assets); len(dtos) > 0 {
			out[i64s(nodeID)] = dtos
		}
	}
	return out
}

// csvValues splits a comma-separated query parameter, dropping empty entries.
func csvValues(s string) []string {
	out := []string{}
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// activity returns the worker execution step log (incremental via ?since=seq).
func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeJSON(w, 200, map[string]any{"items": []any{}, "cursor": 0})
		return
	}
	since := int64(atoiDefault(r.URL.Query().Get("since"), 0))
	limit := atoiDefault(r.URL.Query().Get("limit"), 300)
	var intentPtr *int64
	if iv := r.URL.Query().Get("intent"); iv != "" {
		if n, err := strconv.ParseInt(iv, 10, 64); err == nil {
			intentPtr = &n
		}
	}
	var (
		items  []db.Activity
		cursor int64
		err    error
	)
	if intentPtr != nil {
		items, cursor, err = t.Store.ActivityListWithSources(*intentPtr, since, limit)
	} else {
		items, cursor, err = t.Store.ActivityList(nil, since, limit)
	}
	if err != nil {
		log.Printf("[activity] task=%s since=%d limit=%d intent=%v: %v", t.ID, since, limit, intentPtr, err)
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": activityDTOs(items), "cursor": cursor})
}

// parseActivitySession maps a stable session key (main | plan | intent:<ID>) to a
// DB session filter. Goal Agent + Planner both live under worker="planner" (the
// single Plan session); a Worker session is one intent, keyed by its node id.
func parseActivitySession(sess string) (db.ActivitySessionFilter, bool) {
	switch {
	case sess == "" || sess == "main":
		// bare "main" = the current segment; caller resolves MainSeg via the store.
		return db.ActivitySessionFilter{Main: true}, true
	case strings.HasPrefix(sess, "main:"):
		seg, err := strconv.Atoi(strings.TrimPrefix(sess, "main:"))
		if err != nil || seg < 0 {
			return db.ActivitySessionFilter{}, false
		}
		return db.ActivitySessionFilter{Main: true, MainSeg: &seg}, true
	case sess == "plan":
		return db.ActivitySessionFilter{Worker: "planner"}, true
	case strings.HasPrefix(sess, "intent:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(sess, "intent:"), 10, 64)
		if err != nil {
			return db.ActivitySessionFilter{}, false
		}
		return db.ActivitySessionFilter{NodeID: &id}, true
	}
	return db.ActivitySessionFilter{}, false
}

// activitySessionStore resolves a worker session against the current task and
// its direct sources. Planner/main always stay local; inherited intent sessions
// are immutable history and use the source exploration only for reads.
func activitySessionStore(t *Task, filter db.ActivitySessionFilter) (*db.ExplorationStore, int64, error) {
	if filter.NodeID == nil {
		return t.Store, 0, nil
	}
	node, err := t.Store.GetNodeWithSources(*filter.NodeID)
	if err != nil {
		return nil, 0, err
	}
	if node == nil || node.Kind != db.KindIntent {
		return nil, 0, nil
	}
	if !node.Inherited {
		return t.Store, 0, nil
	}
	if !inheritedIntentResult(node.State) {
		return nil, 0, nil
	}
	sources, err := t.Store.DirectSourceStores()
	if err != nil {
		return nil, 0, err
	}
	for _, source := range sources {
		if source.Task.TaskID == node.SourceTaskID {
			return source.Store, source.Task.TaskID, nil
		}
	}
	return nil, 0, nil
}

// activityHistory serves one reverse-paginated page of a session's activity history.
// The latest page (no ?before) opens a session; ?before=<id> pulls the older page on
// scroll-up. snapshot_cursor is the TASK-level max id at query time — the client uses
// it to open the single task SSE at since=snapshot_cursor so history (id<=cursor) and
// the live tail (id>cursor) meet with no gap and no overlap.
func (s *Server) activityHistory(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	q := r.URL.Query()
	sess := q.Get("session")
	filter, ok := parseActivitySession(sess)
	if !ok {
		writeErr(w, 400, "bad session")
		return
	}
	if filter.Main && filter.MainSeg == nil { // bare "main" → the current segment
		seg, err := t.Store.CurrentMainSeg()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		filter.MainSeg = &seg
	}
	before := int64(atoiDefault(q.Get("before"), 0))
	limit := min(atoiDefault(q.Get("limit"), 200), 500) // cap so one request can't pull an unbounded slice
	store, sourceTaskID, err := activitySessionStore(t, filter)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if store == nil {
		writeErr(w, 404, "session not found")
		return
	}
	// The browser tails only this task's broadcaster. Keep the SSE join cursor
	// local even when the opened worker transcript comes from a related task.
	snapshot, err := t.Store.ActivityMaxID()
	if err != nil {
		log.Printf("[activity/history] task=%s session=%s snapshot: %v", t.ID, sess, err)
		writeErr(w, 500, err.Error())
		return
	}
	var items []db.Activity
	var hasMore bool
	if sourceTaskID > 0 {
		// Source sessions are readable only while the intent remains terminal. The
		// DB query also removes model reasoning/accounting rows from inherited data.
		items, hasMore, err = store.ActivityPageForTerminalIntent(*filter.NodeID, before, limit)
	} else {
		items, hasMore, err = store.ActivityPage(filter, before, limit)
	}
	if err != nil {
		log.Printf("[activity/history] task=%s session=%s before=%d limit=%d: %v", t.ID, sess, before, limit, err)
		writeErr(w, 500, err.Error())
		return
	}
	if sourceTaskID > 0 {
		for i := range items {
			items[i].SourceTaskID = sourceTaskID
			items[i].Inherited = true
		}
	}
	earliest := before
	if len(items) > 0 {
		earliest = items[0].ID
	}
	writeJSON(w, 200, map[string]any{
		"items":           activityDTOs(items),
		"snapshot_cursor": snapshot,
		"earliest_cursor": earliest,
		"has_more":        hasMore,
	})
}

// tokenStats returns per-worker token usage (input/output/cache read/write) for a
// task — main agent, planner, and each work#N.
func (s *Server) tokenStats(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeJSON(w, 200, map[string]any{
			"workers":  []db.TokenUsage{},
			"sessions": []db.SessionTokenUsage{},
			"total":    tokenTotalDTO(db.TokenUsage{}),
		})
		return
	}
	stats, err := t.Store.TokenStatsByWorker()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	sessions, err := t.Store.TokenStatsBySession()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	total, err := t.Store.TokenTotal() // whole-task total (all agents)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"workers": stats, "sessions": sessions, "total": tokenTotalDTO(total)})
}

// tokenDailyStats returns global token consumption aggregated by calendar day
// (UTC) across all tasks for the past ?days=N days (default 30).
func (s *Server) tokenDailyStats(w http.ResponseWriter, r *http.Request) {
	days := atoiDefault(r.URL.Query().Get("days"), 30)
	if s.m.pg == nil {
		writeJSON(w, 200, []any{})
		return
	}
	buckets, err := s.m.pg.TokenDailyAll(days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if buckets == nil {
		buckets = []db.DailyTokenBucket{}
	}
	writeJSON(w, 200, buckets)
}

// conversationTokens returns per-conversation token summaries so the dashboard can
// merge chat (conversation) usage into its per-profile / daily token stats — which
// otherwise count only task (exploration) usage.
func (s *Server) conversationTokens(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeJSON(w, 200, []any{})
		return
	}
	rows, err := s.m.pg.ConversationTokenSummaries()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rows)
}

// streamActivity is the live SSE tail: it replays history after ?since=<seq>, then
// pushes each newly appended activity for the task. The seq cursor makes history +
// live join gap-free; on reconnect the client passes its last seq to catch any
// dropped events. Optional ?intent=<id> scopes the stream to one worker session.
// getLogs returns recent backend log lines (Seq > since), newest-last.
func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	since := int64(atoiDefault(r.URL.Query().Get("since"), 0))
	limit := atoiDefault(r.URL.Query().Get("limit"), 500)
	lines, cursor := logSink.recent(since, limit)
	writeJSON(w, 200, map[string]any{"items": lines, "cursor": cursor})
}

// getLogsHistory returns older log lines from the DB (before a given db_id).
// GET /api/logs/history?before=<db_id>&limit=200
// Returns {items:[LogLine], has_more: bool}.
func (s *Server) getLogsHistory(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeJSON(w, 200, map[string]any{"items": []any{}, "has_more": false})
		return
	}
	before := int64(atoiDefault(r.URL.Query().Get("before"), 0))
	limit := atoiDefault(r.URL.Query().Get("limit"), 200)
	if limit > 500 {
		limit = 500
	}
	// If no before given, return the most recent DB rows (mirrors ring restore).
	var (
		rows []*db.DBLog
		err  error
	)
	if before <= 0 {
		rows, err = s.m.pg.RecentLogs(limit)
	} else {
		rows, err = s.m.pg.ListLogsBefore(before, limit)
	}
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	items := make([]LogLine, 0, len(rows))
	for _, r := range rows {
		items = append(items, LogLine{
			DBID:  r.ID,
			TS:    r.CreatedAt.Format(time.RFC3339),
			Level: r.Level,
			Tag:   r.Tag,
			Text:  r.Text,
		})
	}
	writeJSON(w, 200, map[string]any{"items": items, "has_more": len(rows) == limit})
}

// streamLogs is the live SSE tail of the backend log: replays history after
// ?since=<seq>, then pushes each new line.
func (s *Server) streamLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	since := int64(atoiDefault(r.URL.Query().Get("since"), 0))
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := logSink.subscribe()
	defer unsub()
	send := func(l LogLine) {
		b, _ := json.Marshal(l)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	lines, cursor := logSink.recent(since, 1000)
	for _, l := range lines {
		send(l)
	}
	if cursor > since {
		since = cursor
	}
	flusher.Flush()

	ctx := r.Context()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case l, ok := <-ch:
			if !ok {
				return
			}
			if l.Seq <= since {
				continue
			}
			since = l.Seq
			send(l)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) streamActivity(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	var intentPtr *int64
	if iv := r.URL.Query().Get("intent"); iv != "" {
		if n, err := strconv.ParseInt(iv, 10, 64); err == nil {
			intentPtr = &n
		}
	}
	// Cursor precedence: the browser's automatic reconnect sends Last-Event-ID (the
	// last id it received) — trust it over the query so an auto-reconnect resumes
	// exactly where it dropped. A fresh/manual connect has no header and passes
	// since=<snapshot_cursor> from the history page instead.
	since := int64(atoiDefault(r.URL.Query().Get("since"), 0))
	if le := r.Header.Get("Last-Event-ID"); le != "" {
		if n, err := strconv.ParseInt(le, 10, 64); err == nil {
			since = n
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering

	// Subscribe BEFORE replaying history so events in between aren't lost; dedup the
	// overlap by skipping channel events whose id was already replayed.
	ch, unsub := s.engine.Broadcaster().Subscribe(t.ID)
	defer unsub()

	// Emit a standard SSE id: line so the browser echoes it as Last-Event-ID on
	// auto-reconnect (see cursor precedence above).
	sendSSE := func(a db.Activity) {
		b, _ := json.Marshal(activityDTO(a))
		fmt.Fprintf(w, "id: %d\ndata: %s\n\n", a.ID, b)
		flusher.Flush()
	}

	// Compensate the DB backlog after `since` in batches until caught up. This is the
	// gap between the history snapshot and the live tail — NOT the first-page history
	// (that's the /activity/history endpoint). A long task can have far more than one
	// batch, so loop instead of a single fixed read; on a query error log it and close
	// so the client reconnects and retries from its last id (broadcast is lossy — the
	// DB is the source of truth). The Broadcaster keeps buffering live events meanwhile;
	// the id<=since skip below drops any that this replay already covered.
	const replayBatch = 500
	for {
		items, cursor, err := t.Store.ActivityList(intentPtr, since, replayBatch)
		if err != nil {
			log.Printf("[activity/stream] task=%s replay since=%d: %v", t.ID, since, err)
			return
		}
		for _, a := range items {
			sendSSE(a)
		}
		if cursor > since {
			since = cursor
		}
		if len(items) < replayBatch {
			break
		}
	}
	flusher.Flush()

	ctx := r.Context()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case a, ok := <-ch:
			if !ok {
				return
			}
			if a.ID <= since {
				continue // already replayed
			}
			if intentPtr != nil && (a.NodeID == nil || *a.NodeID != *intentPtr) {
				continue // scoped session: only this intent's steps
			}
			since = a.ID
			sendSSE(a)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// activityDetail lazily returns the full detail blob for one step.
func (s *Server) activityDetail(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no task")
		return
	}
	seq, _ := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	d, err := taskActivityDetail(t, seq)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"detail": d})
}

// taskActivityDetail keeps the legacy local-task behavior (including thinking
// rows), while inherited details are restricted to terminal worker intents.
// This prevents a guessed global activity id from exposing source planner/main
// or in-flight transcripts.
func taskActivityDetail(t *Task, seq int64) (string, error) {
	return t.Store.ActivityDetailWithSources(seq)
}

func (s *Server) getTraffic(w http.ResponseWriter, r *http.Request) {
	tr := s.m.Traffic()
	if tr == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "exchanges": []any{}})
		return
	}
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 0)
	size := atoiDefault(q.Get("size"), 100)
	var taskHosts []string
	taskScoped := false
	if rawTaskID := strings.TrimSpace(q.Get("task_id")); rawTaskID != "" {
		taskScoped = true
		taskID, err := strconv.ParseInt(rawTaskID, 10, 64)
		if err != nil || taskID <= 0 || s.m.ResolveTask(rawTaskID) == nil {
			writeErr(w, http.StatusNotFound, "task not found")
			return
		}
		taskHosts, err = s.m.Assets().HostsByTaskWithSources(taskID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if taskScoped && len(taskHosts) == 0 {
		writeJSON(w, 200, map[string]any{
			"enabled": s.m.TrafficEnabled(), "proxy": s.m.ProxyAddr(), "count": 0,
			"total": 0, "page": page, "size": size, "exchanges": []any{},
		})
		return
	}
	pageQuery := traffic.PageQuery{
		Hosts:   taskHosts,
		Host:    q.Get("host"),
		Method:  q.Get("method"),
		Query:   q.Get("q"),
		Body:    q.Get("body"),
		Path:    q.Get("path"),
		Status:  q.Get("status"),
		RespMin: int64(atoiDefault(q.Get("resp_min"), -1)),
		RespMax: int64(atoiDefault(q.Get("resp_max"), -1)),
		Sort:    q.Get("sort"),
		Order:   q.Get("order"),
	}
	ex, matched, _ := tr.Page(pageQuery, page, size)
	count, _ := tr.Count() // global total, for the stat card
	if taskScoped {
		// matched already represents the current task scope plus all active
		// filters. Reusing it avoids a second full SQLite scan on every refresh.
		count = matched
	}
	writeJSON(w, 200, map[string]any{
		"enabled":   s.m.TrafficEnabled(), // reflect the capture toggle
		"proxy":     s.m.ProxyAddr(),
		"count":     count,   // total recorded (unfiltered)
		"total":     matched, // rows matching the current filter (for pagination)
		"page":      page,
		"size":      size,
		"exchanges": trafficDTOs(ex),
	})
}

// getTrafficHosts returns distinct recorded hosts with counts, for the page's
// target picker (pick a host → filter the list, then delete it).
func (s *Server) getTrafficHosts(w http.ResponseWriter, r *http.Request) {
	tr := s.m.Traffic()
	if tr == nil {
		writeJSON(w, 200, map[string]any{"hosts": []any{}})
		return
	}
	var hosts []string
	if rawTaskID := strings.TrimSpace(r.URL.Query().Get("task_id")); rawTaskID != "" {
		taskID, err := strconv.ParseInt(rawTaskID, 10, 64)
		if err != nil || taskID <= 0 || s.m.ResolveTask(rawTaskID) == nil {
			writeErr(w, http.StatusNotFound, "task not found")
			return
		}
		hosts, err = s.m.Assets().HostsByTaskWithSources(taskID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	var result []traffic.HostCount
	var err error
	if len(hosts) > 0 {
		result, err = tr.HostsForScope(hosts)
	} else if r.URL.Query().Get("task_id") != "" {
		result = []traffic.HostCount{}
	} else {
		result, err = tr.Hosts()
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"hosts": result})
}

// deleteTraffic removes recorded traffic for every host containing the query's
// host substring (the page's host filter is substring-based, so what you
// filtered is what gets deleted): index rows + each host's file tree, then
// garbage-collects blobs no remaining exchange references. Empty host → 400.
// Returns the number of exchanges deleted.
func (s *Server) deleteTraffic(w http.ResponseWriter, r *http.Request) {
	tr := s.m.Traffic()
	if tr == nil {
		writeErr(w, 404, "traffic disabled")
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeErr(w, 400, "missing host")
		return
	}
	n, err := tr.DeleteHost(host)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n})
}

// deleteTrafficHosts removes traffic for a set of EXACT hosts (JSON body
// {"hosts": [...]}) — the batch path for the page's multi-select delete. Exact
// match, so picking "api.example.com" never sweeps "api.example.com.cn".
// Returns the number of exchanges deleted.
func (s *Server) deleteTrafficHosts(w http.ResponseWriter, r *http.Request) {
	tr := s.m.Traffic()
	if tr == nil {
		writeErr(w, 404, "traffic disabled")
		return
	}
	var req struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid body")
		return
	}
	hosts := make([]string, 0, len(req.Hosts))
	for _, h := range req.Hosts {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		writeErr(w, 400, "missing hosts")
		return
	}
	n, err := tr.DeleteHostsExact(hosts)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n})
}

// deleteAllTraffic purges every recorded exchange, then compacts the index so
// the space is actually returned to the filesystem — an emptied index is the one
// moment a full rewrite is cheap. Evidence already bound to a finding lives in
// the evidence store and is deliberately left alone. Returns the number of
// exchanges deleted and the bytes of index reclaimed.
func (s *Server) deleteAllTraffic(w http.ResponseWriter, r *http.Request) {
	tr := s.m.Traffic()
	if tr == nil {
		writeErr(w, 404, "traffic disabled")
		return
	}
	n, reclaimed, err := tr.DeleteAll()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n, "reclaimed": reclaimed})
}

// getTrafficExchange returns the full raw request/response of one exchange,
// read on demand from the traffic tree (bodies are not in the paged list).
func (s *Server) getTrafficExchange(w http.ResponseWriter, r *http.Request) {
	tr := s.m.Traffic()
	if tr == nil {
		writeErr(w, 404, "traffic disabled")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, 400, "missing id")
		return
	}
	req, resp, err := tr.Get(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"req": req, "resp": resp})
}

// getTrafficBlob streams one oversized body by its sha256. Bodies past the inline
// threshold are not carried by the exchange endpoint — it returns a preview plus
// an "@blob sha256:<hash>" pointer — so this is how the UI fetches them whole.
// Streamed rather than buffered: these are the bodies too large to hold in memory.
func (s *Server) getTrafficBlob(w http.ResponseWriter, r *http.Request) {
	tr := s.m.Traffic()
	if tr == nil {
		writeErr(w, 404, "traffic disabled")
		return
	}
	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	if hash == "" {
		writeErr(w, 400, "missing hash")
		return
	}
	f, size, err := tr.Blob(hash)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", hash+".bin"))
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("[traffic] 下载 blob %s 中断：%v", hash, err)
	}
}

// getSettings returns the runtime app settings the UI toggles. The Brave API key
// is returned as a boolean presence flag (brave_key_set), never the value itself,
// so the UI can show "configured" without echoing the secret back.
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.settingsPayload())
}

func (s *Server) settingsPayload() map[string]any {
	on, backend, braveKey, tavilyKey, proxy := s.m.WebSearch()
	pyStored, _, _ := s.m.pg.GetSetting(settingPythonInterp)
	concOn, concLimit := s.m.ConcurrencyLimit()
	if concLimit == 0 {
		concLimit = defaultConcurrencyLimit // 关闭时也回显一个合理默认值给 UI
	}
	return map[string]any{
		"traffic_capture":                      s.m.TrafficEnabled(),
		"browser_screenshot_enabled":           s.m.pg.GetBool(settingBrowserScreenshot, false),
		"browser_screenshot_timestamp_enabled": s.m.pg.GetBool(settingScreenshotTimestamp, false),
		"opsec_enabled":                        s.m.pg.GetBool(settingOpsecEnabled, true),
		"agent_traffic_binding":                s.m.pg.GetBool(settingAgentTrafficBinding, false),
		"task_intelligence_enabled":            s.m.pg.GetBool(db.SettingTaskIntelligence, false),
		db.SettingTaskAutoTitle:                s.m.pg.GetBool(db.SettingTaskAutoTitle, false),
		db.SettingChatAutoTitle:                s.m.pg.GetBool(db.SettingChatAutoTitle, false),
		db.SettingCredentialAgent:              s.m.pg.GetBool(db.SettingCredentialAgent, false),
		db.SettingCredentialTraffic:            s.m.pg.GetBool(db.SettingCredentialAgent, false) && s.m.pg.GetBool(db.SettingCredentialTraffic, false),
		"llm_record":                           s.m.LLMRecordEnabled(),
		"web_search_enabled":                   on,
		"web_search_backend":                   backend,
		"brave_key_set":                        strings.TrimSpace(braveKey) != "",
		"tavily_key_set":                       strings.TrimSpace(tavilyKey) != "",
		"deepseek_search_key_set":              s.m.deepSeekSearchKey() != "",
		"web_search_proxy":                     maskSecrets(proxy),                   // 独立出口代理(http/https/socks5)，空=直连
		"global_proxy":                         maskSecrets(s.m.StaticGlobalProxy()), // 全局出口代理(http/https/socks5)，所有目标流量走它，空=直连
		"exclusive_tor_active":                 s.isExclusiveTorActive(),
		"proxy_pool":                           func() []ProxyPoolEntry { e, _, _ := s.m.ProxyPoolSnapshot(); return e }(),
		"proxy_pool_active_id":                 func() string { _, a, _ := s.m.ProxyPoolSnapshot(); return a }(),
		"proxy_pool_switch_log":                func() []ProxySwitchLog { _, _, l := s.m.ProxyPoolSnapshot(); return l }(),
		"proxy_rotate_timed_enabled":           s.m.pg.GetBool(settingProxyRotateTimed, false),
		"proxy_rotate_interval_seconds":        proxyIntSetting(s.m.pg, settingProxyRotateInterval, defaultProxyRotateInterval),
		"proxy_rotate_on_failure":              s.m.pg.GetBool(settingProxyRotateFailure, false),
		"proxy_rotate_strategy": func() string {
			v, ok, _ := s.m.pg.GetSetting(settingProxyRotateStrategy)
			if ok && (v == "random" || v == "sequential") {
				return v
			}
			return "sequential"
		}(),
		"proxy_health_fail_threshold":         proxyIntSetting(s.m.pg, settingProxyHealthThreshold, defaultProxyHealthThreshold),
		"proxy_health_cooldown_seconds":       proxyIntSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown),
		"proxy_health_check_interval_seconds": proxyIntSetting(s.m.pg, settingProxyHealthInterval, defaultProxyHealthInterval),
		"proxy_reconnect_max_attempts":        func() int { n, _ := s.proxyReconnectConfig(); return n }(),
		"proxy_reconnect_interval_seconds":    func() int { _, d := s.proxyReconnectConfig(); return int(d / time.Second) }(),
		"show_egress_ip":                      s.m.pg.GetBool(settingShowEgressIP, false),
		"egress_probe_url":                    s.m.EgressProbeURL(),
		"python_interpreter":                  strings.TrimSpace(pyStored), // 用户/自动设的值(空=用运行时检测)
		"workers":                             s.m.Workers(),               // 并发工作 agent 数(默认3)；对之后启动的任务生效
		"worker_pools":                        s.m.WorkerPools(),           // 非空时按池顺序绑定 worker 会话
		"task_concurrency_enabled":            concOn,                      // 任务并发上限开关(默认关)
		"task_concurrency_limit":              concLimit,                   // 同时运行任务上限(开启后默认5)
		// LLM 轮询(故障转移)。默认关；开启后走全局激活配置的 agent 在当前配置不可用时
		// 自动切到下一个配置。bind_fallback 仅在轮询开启时有意义(默认关)。
		"llm_pool_enabled":       s.m.LLMPoolEnabled(),
		"llm_pool_bind_fallback": s.m.LLMPoolBindFallback(),
		// 操作约束注入范围(默认都开):把本任务的 allow/deny 约束拼进对应 agent 的系统提示。
		"constraints_inject_planner": s.constraintInjectPlanner(),
		"constraints_inject_worker":  s.constraintInjectWorker(),
		// 实验功能:noa 模型驱动上下文压缩(默认关)。开启后平台接入的四类 agent 由 noa
		// 接管上下文压缩,取代内置 compaction;每 run 读一次,对之后启动的 run 生效。
		"noa_compaction": s.m.NoaCompactionEnabled(),
		// 漏洞 IM 推送的全局项。渠道本身是独立资源，走 /api/notify/* 管理；
		// 这里只放「作用于全部渠道」的三项。
		"notify_enabled":             s.m.pg.GetBool(settingNotifyEnabled, true),
		"notify_public_base_url":     notifyPublicBaseURL(s.m.pg),
		"notify_digest_interval_min": notifyDigestIntervalMin(s.m.pg),
		"turnstile_enabled":          func() bool { en, _, _, _ := s.turnstileConfig(); return en }(),
		"turnstile_site_key":         func() string { _, sk, _, _ := s.turnstileConfig(); return sk }(),
		"turnstile_secret_key_set":   func() bool { _, _, sec, _ := s.turnstileConfig(); return sec != "" }(),
		"turnstile_verified":         func() bool { _, _, _, ver := s.turnstileConfig(); return ver }(),
		"git_autosync_enabled":       s.m.pg.GetBool("git_autosync_enabled", true),
	}
}

// notifyPublicBaseURL 读推送回链用的外部地址。
func notifyPublicBaseURL(pg *db.DB) string {
	v, _, _ := pg.GetSetting(settingNotifyPublicBaseURL)
	return v
}

// notifyDigestIntervalMin 读汇总周期（分钟），非法或未配置时回落到默认值。
// 回显默认值而不是空串，UI 才能把当前生效值填进输入框。
func notifyDigestIntervalMin(pg *db.DB) int {
	v, ok, _ := pg.GetSetting(settingNotifyDigestMinutes)
	if !ok {
		return notifyDefaultDigestMinutes
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return notifyDefaultDigestMinutes
	}
	return n
}

// pgDetectPython re-runs interpreter detection, stores + returns it.
func (s *Server) pgDetectPython(w http.ResponseWriter, r *http.Request) {
	p := detectPython()
	if p == "" {
		writeErr(w, 404, "未检测到 python(python3/python 均不在 PATH)")
		return
	}
	if err := s.m.pg.SetSetting(settingPythonInterp, p); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"python_interpreter": p})
}

// putSettings applies a settings change. Toggling traffic_capture rebuilds the
// agents (applyLLM) so the new proxy/traffic-tools/prompt state takes hold — when
// off, agents get no proxy config, no traffic tools, and no proxy prompt content.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TrafficCapture      *bool `json:"traffic_capture"`
		BrowserScreenshot   *bool `json:"browser_screenshot_enabled"`
		ScreenshotTimestamp *bool `json:"browser_screenshot_timestamp_enabled"`
		OpsecEnabled        *bool `json:"opsec_enabled"`
		AgentTrafficBinding *bool `json:"agent_traffic_binding"`
		TaskIntelligence    *bool `json:"task_intelligence_enabled"`
		TaskAutoTitle       *bool `json:"task_auto_title_enabled"`
		ChatAutoTitle       *bool `json:"chat_auto_title_enabled"`
		CredentialAgent     *bool `json:"credential_agent_enabled"`
		CredentialTraffic   *bool `json:"credential_traffic_binding"`
		LLMRecord           *bool `json:"llm_record"` // LLM 录制开关（默认关）；即时生效，无需重建 agent
		// Web search. WebSearchEnabled/Backend toggle the tool + backend; BraveKey/TavilyKey
		// are optional — omit (null) to leave a stored key untouched, send "" to clear.
		WebSearchEnabled       *bool         `json:"web_search_enabled"`
		WebSearchBackend       *string       `json:"web_search_backend"`
		BraveKey               *string       `json:"brave_search_api_key"`
		TavilyKey              *string       `json:"tavily_search_api_key"`
		DeepSeekSearchKey      *string       `json:"deepseek_search_api_key"`
		WebSearchProxy         *string       `json:"web_search_proxy"` // 独立出口代理(http/https/socks5)；null=不改，""=清空
		GlobalProxy            *string       `json:"global_proxy"`     // 全局出口代理(http/https/socks5)；null=不改，""=清空(直连)
		ProxyRotateTimed       *bool         `json:"proxy_rotate_timed_enabled"`
		ProxyRotateInterval    *int          `json:"proxy_rotate_interval_seconds"`
		ProxyRotateFailure     *bool         `json:"proxy_rotate_on_failure"`
		ProxyRotateStrategy    *string       `json:"proxy_rotate_strategy"`
		ProxyHealthThreshold   *int          `json:"proxy_health_fail_threshold"`
		ProxyHealthCooldown    *int          `json:"proxy_health_cooldown_seconds"`
		ProxyHealthInterval    *int          `json:"proxy_health_check_interval_seconds"`
		ProxyReconnectMax      *int          `json:"proxy_reconnect_max_attempts"`
		ProxyReconnectInterval *int          `json:"proxy_reconnect_interval_seconds"`
		ShowEgressIP           *bool         `json:"show_egress_ip"`     // 在顶栏显示直连/全局代理出口 IP；默认关
		EgressProbeURL         *string       `json:"egress_probe_url"`   // null=不改；空串=默认公共探测服务
		PythonInterp           *string       `json:"python_interpreter"` // 自定义脚本工具的 python 解释器路径
		Workers                *int          `json:"workers"`            // 并发工作 agent 数(>0)；对之后启动的任务生效
		WorkerPools            *[]WorkerPool `json:"worker_pools"`
		// 任务并发上限:同时「运行中」的任务数上限。关闭=不限;开启后新建任务超限则排队,有空位自动启动。
		ConcurrencyEnabled *bool `json:"task_concurrency_enabled"`
		ConcurrencyLimit   *int  `json:"task_concurrency_limit"`
		// LLM 轮询(故障转移)开关 + 「绑定配置失败也兜底回轮询链」开关。两者都需要
		// 重建 provider 链才生效，走下面的 changed → applyLLM 路径。
		LLMPoolEnabled      *bool `json:"llm_pool_enabled"`
		LLMPoolBindFallback *bool `json:"llm_pool_bind_fallback"`
		// 操作约束注入范围开关(默认都开);即时生效(planner/worker 每轮读),无需重建 agent。
		ConstraintsInjectPlanner *bool `json:"constraints_inject_planner"`
		ConstraintsInjectWorker  *bool `json:"constraints_inject_worker"`
		// 实验功能:noa 上下文压缩开关(默认关);每 run 读,对之后启动的 run 生效,无需重建 agent。
		NoaCompaction *bool `json:"noa_compaction"`
		// 漏洞 IM 推送的全局项。三者都由投递引擎每轮读一次，改完即时生效，
		// 不需要重建 agent 或重启。
		NotifyEnabled      *bool   `json:"notify_enabled"`
		NotifyBaseURL      *string `json:"notify_public_base_url"`
		NotifyDigestMins   *int    `json:"notify_digest_interval_min"`
		TurnstileEnabled   *bool   `json:"turnstile_enabled"`
		TurnstileSiteKey   *string `json:"turnstile_site_key"`
		TurnstileSecretKey *string `json:"turnstile_secret_key"`
		GitAutoSyncEnabled *bool   `json:"git_autosync_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.EgressProbeURL != nil {
		value := strings.TrimSpace(*req.EgressProbeURL)
		if value != "" {
			checked, err := validateProbeURL(value)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			value = checked
		}
		req.EgressProbeURL = &value
	}
	if req.ConstraintsInjectPlanner != nil {
		if err := s.m.pg.SetBool(settingConstraintsInjectPlanner, *req.ConstraintsInjectPlanner); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.ConstraintsInjectWorker != nil {
		if err := s.m.pg.SetBool(settingConstraintsInjectWorker, *req.ConstraintsInjectWorker); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.NoaCompaction != nil {
		// 每 run 读的解析器,切换即时对之后启动的 run 生效,无需 applyLLM 重建。
		if err := s.m.SetNoaCompaction(*req.NoaCompaction); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	// 推送全局项:投递引擎每轮重新读取,所以即时生效、无需重启。
	if req.NotifyEnabled != nil {
		if err := s.m.pg.SetBool(settingNotifyEnabled, *req.NotifyEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.NotifyBaseURL != nil {
		// 统一裁掉尾部斜杠:回链拼接用的是 fmt.Sprintf("%s/function/..."),
		// 留着尾部斜杠会产出 "//function/..." 这种双斜杠路径。
		base := trimTrailingSlash(strings.TrimSpace(*req.NotifyBaseURL))
		if base != "" && !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			writeErr(w, 400, "回链地址需以 http:// 或 https:// 开头")
			return
		}
		if err := s.m.pg.SetSetting(settingNotifyPublicBaseURL, base); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.NotifyDigestMins != nil {
		// 下限 1 分钟:更短的周期等于实时推送,那样应该直接把渠道改成 realtime 模式。
		if *req.NotifyDigestMins < 1 || *req.NotifyDigestMins > 24*60 {
			writeErr(w, 400, "Digest interval must be between 1 and 1440 minutes")
			return
		}
		if err := s.m.pg.SetSetting(settingNotifyDigestMinutes, strconv.Itoa(*req.NotifyDigestMins)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.TurnstileEnabled != nil {
		if err := s.m.pg.SetBool("turnstile_enabled", *req.TurnstileEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.TurnstileSiteKey != nil || req.TurnstileSecretKey != nil {
		_, curSite, curSec, _ := s.turnstileConfig()
		nextSite := curSite
		nextSec := curSec
		if req.TurnstileSiteKey != nil {
			nextSite = strings.TrimSpace(*req.TurnstileSiteKey)
		}
		if req.TurnstileSecretKey != nil {
			nextSec = strings.TrimSpace(*req.TurnstileSecretKey)
		}
		// If the user cleared Site Key, clear Secret Key as well so built-in gate resumes cleanly.
		if req.TurnstileSiteKey != nil && nextSite == "" && req.TurnstileSecretKey == nil {
			nextSec = ""
		}
		if (nextSite != "" && nextSec == "") || (nextSite == "" && nextSec != "") {
			writeErr(w, 400, "Provide both Turnstile Site Key and Turnstile Secret Key (or clear both to use the built-in gate)")
			return
		}
		if nextSite != "" && nextSec != "" {
			if err := verifyTurnstileSecretKey(nextSec); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			if err := s.m.pg.SetSetting("turnstile_site_key", nextSite); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			if err := s.m.pg.SetSetting("turnstile_secret_key", nextSec); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			_ = s.m.pg.SetSetting("turnstile_keys_verified", "true")
		} else {
			_ = s.m.pg.SetSetting("turnstile_site_key", "")
			_ = s.m.pg.SetSetting("turnstile_secret_key", "")
			_ = s.m.pg.SetSetting("turnstile_keys_verified", "false")
		}
	}
	if req.GitAutoSyncEnabled != nil {
		if err := s.m.pg.SetBool("git_autosync_enabled", *req.GitAutoSyncEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		maintState.mu.Lock()
		maintState.AutoSyncOn = *req.GitAutoSyncEnabled
		maintState.mu.Unlock()
	}
	// A non-empty pool list takes precedence when both fields are present and
	// synchronizes workers to its total. An empty list clears pools; when workers
	// is also present it sets the legacy count for the newly restored legacy mode.
	if req.WorkerPools != nil {
		if len(*req.WorkerPools) == 0 && req.Workers != nil && *req.Workers <= 0 {
			writeErr(w, 400, "workers 必须 >0")
			return
		}
		legacyWorkers := []int(nil)
		if req.Workers != nil {
			legacyWorkers = []int{*req.Workers}
		}
		if err := s.m.SetWorkerPools(*req.WorkerPools, legacyWorkers...); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	} else if req.Workers != nil {
		// An omitted worker_pools field leaves the saved mode unchanged. If a
		// non-empty pool configuration is already saved, its total remains the
		// authoritative concurrency and workers is deliberately ignored.
		if len(s.m.WorkerPools()) == 0 {
			if err := s.m.SetWorkers(*req.Workers); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
		}
	}
	if req.ConcurrencyEnabled != nil || req.ConcurrencyLimit != nil {
		// 部分 PUT:未给的字段用当前值兜底,避免只改一个把另一个重置。
		curOn, curLimit := s.m.ConcurrencyLimit()
		if curLimit == 0 {
			curLimit = defaultConcurrencyLimit
		}
		on, limit := curOn, curLimit
		if req.ConcurrencyEnabled != nil {
			on = *req.ConcurrencyEnabled
		}
		if req.ConcurrencyLimit != nil {
			limit = *req.ConcurrencyLimit
		}
		if err := s.m.SetConcurrency(on, limit); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		// 立即协调一次:关闭时放行全部排队,调高上限时补位启动,不必等下一个 tick。
		go s.reconcileConcurrency()
	}
	if req.PythonInterp != nil {
		if err := s.m.pg.SetSetting(settingPythonInterp, strings.TrimSpace(*req.PythonInterp)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.LLMRecord != nil {
		// 录制器每次调用读取该标志，切换即时生效，无需 applyLLM 重建。
		if err := s.m.SetLLMRecordEnabled(*req.LLMRecord); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	changed := false
	if req.LLMPoolEnabled != nil {
		if err := s.m.SetLLMPoolEnabled(*req.LLMPoolEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		changed = true // the provider chain itself changes shape → rebuild
	}
	if req.LLMPoolBindFallback != nil {
		if err := s.m.SetLLMPoolBindFallback(*req.LLMPoolBindFallback); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		changed = true
	}
	if req.LLMPoolEnabled != nil || req.LLMPoolBindFallback != nil {
		// Pinned tasks' planner/worker and per-profile chat agents hold providers
		// built under the OLD switch state — drop them so they pick up the new one.
		s.invalidateProfileAgents()
	}
	if req.TaskIntelligence != nil || req.CredentialAgent != nil || req.CredentialTraffic != nil {
		if err := s.m.pg.SetIntelligenceSettings(r.Context(), req.TaskIntelligence, req.CredentialAgent, req.CredentialTraffic); err != nil {
			intelligenceError(w, err)
			return
		}
	}
	if req.TaskAutoTitle != nil {
		if err := s.m.pg.SetBool(db.SettingTaskAutoTitle, *req.TaskAutoTitle); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.ChatAutoTitle != nil {
		if err := s.m.pg.SetBool(db.SettingChatAutoTitle, *req.ChatAutoTitle); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.AgentTrafficBinding != nil {
		if err := s.m.pg.SetBool(settingAgentTrafficBinding, *req.AgentTrafficBinding); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.BrowserScreenshot != nil {
		if err := s.setReporterBrowserScreenshotVisibility(*req.BrowserScreenshot); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if err := s.m.pg.SetBool(settingBrowserScreenshot, *req.BrowserScreenshot); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		// The reporter's MCP visibility and prompt are assembled when agents are
		// built. Rebuild immediately so the setting applies to the next run,
		// rather than only after a later unrelated LLM/settings change.
		changed = true
	}
	if req.ScreenshotTimestamp != nil {
		if err := s.m.pg.SetBool(settingScreenshotTimestamp, *req.ScreenshotTimestamp); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.OpsecEnabled != nil {
		if err := s.m.pg.SetBool(settingOpsecEnabled, *req.OpsecEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.TrafficCapture != nil {
		if err := s.m.SetTrafficEnabled(*req.TrafficCapture); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		changed = true
	}
	if req.GlobalProxy != nil {
		globalProxyValue := strings.TrimSpace(*req.GlobalProxy)
		if strings.Contains(globalProxyValue, "***") || strings.Contains(globalProxyValue, "******") {
			globalProxyValue = s.m.StaticGlobalProxy()
		}
		if globalProxyValue != "" && s.isExclusiveTorActive() {
			s.shutdownExclusiveTor()
		}
		var proxyGuards map[string]proxyReconnectGuard
		if globalProxyValue == "" {
			proxyGuards = s.snapshotProxyReconnectGuards(false)
		}
		// Validation failure (bad scheme/host) is a client error, not a 500.
		if err := s.m.SetGlobalProxy(globalProxyValue); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if globalProxyValue == "" && (s.m.proxyPool == nil || len(s.m.proxyPoolEntries()) == 0) {
			s.proxyReconnectSuccessWithGuards(proxyGuards, nil)
		}
		if ppV2 == nil || ppV2.Pool == nil || ppV2.Pool.GetStats().Total == 0 {
			s.syncV1ToProxyPoolV2()
		}
		changed = true
	}
	if req.ProxyReconnectMax != nil || req.ProxyReconnectInterval != nil {
		if err := s.setProxyReconnectSettings(req.ProxyReconnectMax, req.ProxyReconnectInterval); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if req.ProxyRotateTimed != nil || req.ProxyRotateInterval != nil || req.ProxyRotateFailure != nil || req.ProxyRotateStrategy != nil || req.ProxyHealthThreshold != nil || req.ProxyHealthCooldown != nil || req.ProxyHealthInterval != nil {
		timed, interval, onFailure, strategy := s.m.proxyRotateConfig()
		threshold, cooldown, healthInterval := s.m.proxyHealthConfig()
		if req.ProxyRotateTimed != nil {
			timed = *req.ProxyRotateTimed
		}
		if req.ProxyRotateInterval != nil {
			interval = time.Duration(*req.ProxyRotateInterval) * time.Second
		}
		if req.ProxyRotateFailure != nil {
			onFailure = *req.ProxyRotateFailure
		}
		if req.ProxyRotateStrategy != nil {
			strategy = strings.TrimSpace(*req.ProxyRotateStrategy)
		}
		if req.ProxyHealthThreshold != nil {
			threshold = *req.ProxyHealthThreshold
		}
		if req.ProxyHealthCooldown != nil {
			cooldown = time.Duration(*req.ProxyHealthCooldown) * time.Second
		}
		if req.ProxyHealthInterval != nil {
			healthInterval = time.Duration(*req.ProxyHealthInterval) * time.Second
		}
		if err := s.m.SetProxyPoolSettings(timed, int(interval/time.Second), onFailure, strategy, threshold, int(cooldown/time.Second), int(healthInterval/time.Second)); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		select {
		case s.proxyPoolWake <- struct{}{}:
		default:
		}
	}
	if req.EgressProbeURL != nil {
		if err := s.m.pg.SetSetting(settingEgressProbeURL, *req.EgressProbeURL); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.ShowEgressIP != nil {
		if err := s.m.pg.SetBool(settingShowEgressIP, *req.ShowEgressIP); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.WebSearchEnabled != nil || req.WebSearchBackend != nil || req.BraveKey != nil || req.TavilyKey != nil || req.DeepSeekSearchKey != nil || req.WebSearchProxy != nil {
		// Fill unspecified fields from current state so a partial PUT doesn't reset them.
		on, backend, _, _, _ := s.m.WebSearch()
		if req.WebSearchEnabled != nil {
			on = *req.WebSearchEnabled
		}
		if req.WebSearchBackend != nil {
			backend = *req.WebSearchBackend
		}
		if req.WebSearchProxy != nil && (strings.Contains(*req.WebSearchProxy, "***") || strings.Contains(*req.WebSearchProxy, "******")) {
			_, _, _, _, savedSearchProxy := s.m.WebSearch()
			req.WebSearchProxy = &savedSearchProxy
		}
		if err := s.m.SetWebSearch(on, backend, req.BraveKey, req.TavilyKey, req.WebSearchProxy); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if req.TavilyKey != nil && s.searchOrchestrator != nil {
			s.searchOrchestrator.UpdateEngine("tavily", *req.TavilyKey)
		}
		changed = true
	}
	if req.DeepSeekSearchKey != nil {
		if strings.Contains(*req.DeepSeekSearchKey, "***") {
			*req.DeepSeekSearchKey = s.m.deepSeekSearchKey()
		}
		if err := s.m.setDeepSeekSearchKey(*req.DeepSeekSearchKey); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		changed = true
	}
	if changed {
		// rebuild agents so the new proxy/tools/prompt/web-search take hold (only if LLM configured).
		s.cfgMu.Lock()
		cfg, on := s.llmCfg, s.llmOn
		s.cfgMu.Unlock()
		if on {
			if err := s.applyLLM(cfg); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
		}
	}
	writeJSON(w, 200, s.settingsPayload())
}

// setReporterBrowserScreenshotVisibility keeps the report writer's browser MCP
// permission in sync with the screenshot setting. Other agents retain their
// explicit MCP permissions.
func (s *Server) setReporterBrowserScreenshotVisibility(enabled bool) error {
	reporter, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil {
		return err
	}
	servers, err := s.m.pg.ListMCP()
	if err != nil {
		return err
	}
	for _, server := range servers {
		if server.Name == browserMCPName {
			// Turning screenshots on is an explicit opt-in. Make the browser MCP
			// usable in the shipped root-based container at the same time as the
			// permission toggle, so the next reporter run gets a working browser
			// instead of a deterministic Chromium sandbox error.
			if enabled {
				server.Args = encodeJSON(ensureBrowserMCPArgs(decodeStrSlice(server.Args), true))
				server.Enabled = true
				if _, err := s.m.pg.SaveMCP(server); err != nil {
					return err
				}
			}
			return s.m.pg.ToggleVisibility(reporter.ID, "mcp", server.ID, enabled)
		}
	}
	// The built-in browser MCP may be deleted by an administrator. Keep the
	// setting writable so it takes effect automatically if the server returns.
	return nil
}

// testWebSearch runs a real "test" search with the given (or currently saved)
// backend/proxy/key to verify the config can actually reach a search backend —
// mirroring testLLM. Backend/proxy come from the request (so the form's unsaved
// edits are tested); empty API keys fall back to stored values so the user need
// not retype them. Always 200 with {ok, error?, count?, backend?}.
func (s *Server) testWebSearch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Backend           string `json:"web_search_backend"`
		Proxy             string `json:"web_search_proxy"`
		BraveKey          string `json:"brave_search_api_key"`
		TavilyKey         string `json:"tavily_search_api_key"`
		DeepSeekSearchKey string `json:"deepseek_search_api_key"`
	}
	// Empty body is fine — fall back entirely to the saved config below.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeErr(w, 400, err.Error())
		return
	}
	_, backend, storedBraveKey, storedTavilyKey, _ := s.m.WebSearch()
	if strings.TrimSpace(req.Backend) != "" {
		backend = req.Backend
	}
	// Proxy is taken from the form as-is (empty = direct), so testing reflects exactly
	// what's shown — including an intentional "clear proxy to test direct" before saving.
	proxy := strings.TrimSpace(req.Proxy)
	// API keys are secrets the form omits when already saved, so fall back to stored.
	braveKey := storedBraveKey
	if strings.TrimSpace(req.BraveKey) != "" {
		braveKey = req.BraveKey
	}
	tavilyKey := storedTavilyKey
	if strings.TrimSpace(req.TavilyKey) != "" {
		tavilyKey = req.TavilyKey
	}
	deepSeekKey := s.m.deepSeekSearchKey()
	if strings.TrimSpace(req.DeepSeekSearchKey) != "" {
		deepSeekKey = strings.TrimSpace(req.DeepSeekSearchKey)
	}
	cfg := actool.WebSearchConfig{Backend: backend, BraveAPIKey: braveKey, TavilyAPIKey: tavilyKey, Proxy: proxy}
	// Hard cap so a slow/blocked proxy can't hang the request.
	wall := 30 * time.Second
	probeQuery := "test"
	if strings.TrimSpace(backend) == deepSeekWebSearchBackend {
		ctx, cancel := context.WithTimeout(r.Context(), wall)
		defer cancel()
		count, err := agent.DeepSeekSearchProbe(ctx, deepSeekKey, proxy, "DeepSeek company official website", 3)
		if err != nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "backend": backend})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": count > 0, "count": count, "backend": backend})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), wall)
	defer cancel()
	results, err := actool.WebSearchProbe(ctx, cfg, probeQuery, 3)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "backend": backend})
		return
	}
	if len(results) == 0 {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "搜索返回 0 条结果（可能被限流或代理不通）", "backend": backend})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "count": len(results), "backend": backend})
}

// mainSessions lists the task's main-agent conversation segments (newest-first) and
// the current one. The frontend renders these as switchable sessions under 主 Agent.
func (s *Server) mainSessions(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	list, err := t.Store.ListMainSessions()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	current := 0
	if len(list) > 0 {
		current = list[0].Seq // newest-first
	}
	writeJSON(w, 200, map[string]any{"sessions": list, "current": current})
}

// newMainSession starts a fresh main-agent conversation segment. Only the segment
// counter advances — the task's exploration graph, assets and goal are untouched, so
// the main agent continues over the same task with a clean transcript/context.
func (s *Server) newMainSession(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	if s.engine.IsDeleting(t.ID) {
		writeErr(w, 409, "任务正在删除，无法新建会话")
		return
	}
	m, err := t.Store.NewMainSession()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"seq": m.Seq, "created_at": rfc3339(m.CreatedAt), "current": m.Seq})
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	if s.engine.IsDeleting(t.ID) {
		writeErr(w, 409, "任务正在删除，无法发送新消息")
		return
	}
	// 注意:任务暂停(paused)不拦截主 Agent 对话。主 Agent 编排会话独立于 planner/
	// worker 的暂停,暂停中仍可继续对话(暂停只终止其正在进行的那一轮,见 control())。
	var req struct {
		Message     string           `json:"message"`
		Attachments []chatAttachment `json:"attachments,omitempty"` // 方式1 上传的文件(路径相对任务工作目录)
		Seg         *int             `json:"seg,omitempty"`         // 目标主会话分段;缺省=最新段
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	agentMessage, ok := s.prepareChatMentionMessage(w, req.Message)
	if !ok {
		return
	}
	// Admission is serialized with deletion's chat cancellation. Mark every chat
	// turn busy before its first activity/file write, including rule-mode turns.
	// If deletion wins the race, the second barrier check rejects this request.
	s.chatMu.Lock()
	if s.engine.IsDeleting(t.ID) {
		s.chatMu.Unlock()
		writeErr(w, 409, "任务正在删除，无法发送新消息")
		return
	}
	if s.chatBusy[t.ID] {
		s.chatMu.Unlock()
		writeErr(w, 409, "主 Agent 正在处理上一条消息，请稍候")
		return
	}
	ctx, cancel := context.WithCancelCause(s.ctx)
	ctx = intercept.WithReviewContext(ctx, "", intercept.ReviewBackground{Source: intercept.BackgroundUserMessage, Text: req.Message})
	s.chatBusy[t.ID] = true
	s.chatCancel[t.ID] = cancel
	s.chatMu.Unlock()

	// The turn belongs to whichever main-agent segment the user is chatting in (any
	// segment is interactive, like the top-level chat conversations). Stamp every
	// mainagent row with it so this turn's transcript + activity land in that segment.
	// Missing seg (older clients) falls back to the newest segment.
	mainSeg := 0
	if req.Seg != nil && *req.Seg >= 0 {
		mainSeg = *req.Seg
	} else {
		mainSeg, _ = t.Store.CurrentMainSeg()
	}
	segPtr := &mainSeg

	// Persist + broadcast the human turn so the 主 Agent 编排会话 survives page
	// reloads and updates live: the conversation lives in the activity stream as
	// worker="mainagent" (the per-task activity table, replayed via SSE). With
	// attachments, the activity's Detail carries {text, attachments} so the transcript
	// renders attachment cards.
	humanTurn := userActivityWithAttachments("mainagent", req.Message, req.Attachments)
	humanTurn.MainSeg = segPtr
	s.engine.emitActivity(t, humanTurn)
	var ma *agent.MainAgent
	if s.taskRuntimeAvailable(t, "mainagent") {
		ma = s.agentsForTask(t).main
	}
	if ma != nil {
		s.registerActiveTurn(persistedInFlightTurn{
			Kind:        "task_main",
			BusyKey:     t.ID,
			TaskID:      t.ID,
			MainSeg:     mainSeg,
			OriginalMsg: req.Message,
		})
		// Run the agent on a per-turn cancellable ctx (NOT r.Context()): the turn can
		// take minutes (multi-tool loop), and binding it to the request lifecycle meant
		// a page reload / proxy timeout cancelled it mid-run ("context canceled"). The
		// steps + final answer stream back live via SSE (worker="mainagent"), so the
		// handler returns immediately and the browser never needs to hold the request.
		go func() {
			defer func() {
				if !isLiveUpdateReloadContext(ctx) {
					s.unregisterActiveTurn(t.ID)
				}
				s.finishTaskChat(t.ID, cancel)
			}()
			// emit every step (thinking/tool_use/tool_result/text/result) so the main
			// agent session shows its work live, like worker/planner. The final answer
			// is the captured "result" step — no separate reply emit (would duplicate).
			emit := func(rec db.Activity) {
				rec.MainSeg = segPtr
				s.engine.emitActivity(t, rec)
			}
			maTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
			resume := func() { s.reviveTask(t) } // set_goals 新增目标 → 把任务拉回 running
			// 把上传附件的【绝对路径】清单拼进发给 agent 的消息,它据此用 Read/Bash 打开文件。
			// taskDir = agent 的工作目录(CWD),与 chatUpload 落盘、ensureRunDir 一致。
			taskDir := filepath.Join(s.m.dir, "tasks", t.ID)
			agentMsg := composeAgentMessage(agentMessage, req.Attachments, taskDir)
			s.engine.BeginLLMCall(t.ID)
			_, err := ma.Chat(ctx, maTaskID, mainSeg, s.m.Assets(), t.Store, t.Goal, agentMsg, emit, t.Notify, resume, t.NotifyGoal, t.NotifyHint)
			s.engine.EndLLMCall(t.ID)
			if err != nil && ctx.Err() == nil {
				s.engine.emitActivity(t, db.Activity{Worker: "mainagent", Kind: "text", IsError: true, Summary: "Main Agent error: " + err.Error(), MainSeg: segPtr})
			}
		}()
		writeJSON(w, 202, map[string]any{"status": "accepted", "mode": "llm"})
		return
	}
	reply := s.fallbackChat(t, req.Message)
	s.engine.emitActivity(t, db.Activity{Worker: "mainagent", Kind: "text", Summary: reply, MainSeg: segPtr})
	s.finishTaskChat(t.ID, cancel)
	writeJSON(w, 200, map[string]any{"reply": reply, "mode": "rule"})
}

func (s *Server) cancelTaskChat(taskID string, cause error) bool {
	s.unregisterActiveTurn(taskID)
	s.chatMu.Lock()
	cancel := s.chatCancel[taskID]
	if cancel != nil {
		cancel(cause)
	}
	s.chatMu.Unlock()
	return cancel != nil
}

func (s *Server) finishTaskChat(taskID string, cancel context.CancelCauseFunc) {
	cancel(agent.AbortChatTurnFinished)
	s.chatMu.Lock()
	delete(s.chatBusy, taskID)
	delete(s.chatCancel, taskID)
	s.chatMu.Unlock()
}

// taskChatStatus reports the authoritative state of the task's main-agent turn.
// Activity timestamps are not a reliable proxy because a tool or LLM call may run
// for minutes without emitting an intermediate frame.
func (s *Server) taskChatStatus(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.PathValue("id"))
	if t == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	s.chatMu.Lock()
	running := s.chatBusy[t.ID]
	s.chatMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"running": running})
}

// stopChat aborts the in-flight main-agent turn for a task (manual stop button).
// Mirrors pgStopConversation: cancels only the current turn; planner/workers are
// unaffected and continue running. The user can send a new message immediately.
func (s *Server) stopChat(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.PathValue("id"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.cancelTaskChat(t.ID, agent.AbortChatStoppedByUser) {
		writeJSON(w, 200, map[string]any{"status": "idle"})
		return
	}
	writeJSON(w, 200, map[string]any{"status": "stopping"})
}

// fallbackChat is the no-LLM human-steering handler: simple命令 + 态势摘要.
func (s *Server) fallbackChat(t *Task, msg string) string {
	m := strings.TrimSpace(msg)
	lower := strings.ToLower(m)
	switch {
	case strings.HasPrefix(m, "意图") || strings.HasPrefix(lower, "intent"):
		text := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(m, "意图"), "intent"))
		_, _ = t.Store.AddIntent(map[string]any{"summary": text}, 9, nil, "human")
		return "已注入一条高优先级意图：" + text
	case strings.HasPrefix(m, "提示") || strings.HasPrefix(lower, "hint"):
		text := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(m, "提示"), "hint"))
		_, _ = t.Store.AddNode(db.KindHint, map[string]any{"text": text}, 0, "active", "human", nil)
		return "已记录提示，规划者下次会读到：" + text
	default:
		assetCounts, _ := s.m.Assets().CountsByType()
		assets := 0
		for _, c := range assetCounts {
			assets += c
		}
		fnd, _ := t.Store.ListByKind(db.KindFinding, 1000)
		fr, _ := t.Store.Frontier(1000)
		return fmt.Sprintf("（规则模式，未配置 LLM）当前态势：资产 %d，待领意图 %d，确认发现 %d。\n可用指令：以\"意图 ...\"注入意图，\"提示 ...\"给规划者提示。", assets, len(fr), len(fnd))
	}
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	findings, _ := t.Store.ListByKind(db.KindFinding, 1000)
	goals, _ := t.Store.ListByKind(db.KindGoal, 500)
	hints, _ := t.Store.ListByKind(db.KindHint, 200)
	facts, _ := t.Store.ListByKind(db.KindFact, 1000)
	constraints, _ := t.Store.ListConstraints()
	edges, _ := t.Store.Edges(5000)

	dbFindings, _ := s.m.pg.ListFindingsForExport(db.FindingFilter{TaskID: t.ID}, nil)
	for _, df := range dbFindings {
		if df == nil {
			continue
		}
		if tf, err := s.m.pg.GetFindingTraffic(r.Context(), df.ID); err == nil && tf != nil {
			df.TrafficBindings = tf.Bindings
		}
	}

	findingChains := map[int64][]*db.Node{}
	for _, fn := range findings {
		if fn == nil {
			continue
		}
		if chainNodes, _, err := t.Store.FindingLineage(fn.ID); err == nil && len(chainNodes) > 0 {
			findingChains[fn.ID] = chainNodes
		}
	}

	intentNodes, _ := t.Store.ListByKind(db.KindIntent, 500)
	sort.Slice(intentNodes, func(i, j int) bool { return intentNodes[i].ID < intentNodes[j].ID })
	derivedMap := map[int64][]int64{}
	yieldedMap := map[int64][]int64{}
	for _, e := range edges {
		switch e.Rel {
		case "derived_from":
			derivedMap[e.From] = append(derivedMap[e.From], e.To)
		case "yields":
			yieldedMap[e.From] = append(yieldedMap[e.From], e.To)
		}
	}
	intents := make([]report.IntentTrace, 0, len(intentNodes))
	intentTitles := map[int64]string{}
	for _, inNode := range intentNodes {
		if inNode == nil || inNode.State == "deleted" {
			continue
		}
		var ip struct {
			Summary string `json:"summary"`
			Title   string `json:"title"`
		}
		_ = json.Unmarshal(inNode.Payload, &ip)
		if ip.Summary != "" {
			intentTitles[inNode.ID] = ip.Summary
		} else if ip.Title != "" {
			intentTitles[inNode.ID] = ip.Title
		}
		steps, _ := t.Store.ActivityTraceWithSources(inNode.ID, 100)
		intents = append(intents, report.IntentTrace{
			Node:       inNode,
			DerivedIDs: derivedMap[inNode.ID],
			YieldedIDs: yieldedMap[inNode.ID],
			Steps:      steps,
		})
	}

	md := s.buildTaskReportMarkdown(r.Context(), t, taskID, findings, dbFindings, findingChains, goals, hints, facts, constraints, edges, intents, intentTitles)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(md))
}

func (s *Server) buildTaskReportMarkdown(
	ctx context.Context,
	t *Task,
	taskID int64,
	findings []*db.Node,
	dbFindings []*db.DBFinding,
	findingChains map[int64][]*db.Node,
	goals []*db.Node,
	hints []*db.Node,
	facts []*db.Node,
	constraints []db.Constraint,
	edges []db.Edge,
	intents []report.IntentTrace,
	intentTitles map[int64]string,
) string {
	var scopeVals []string
	if as := s.m.Assets(); as != nil && taskID > 0 {
		if rows, err := as.ListTaskScopeWithSources(taskID); err == nil {
			for _, sr := range rows {
				if strings.TrimSpace(sr.Value) != "" {
					scopeVals = append(scopeVals, fmt.Sprintf("%s:%s", sr.Kind, sr.Value))
				}
			}
		}
	}

	counts := map[string]int{}
	var assetEntries []report.AssetEntry
	assetLabels := map[int64]string{}
	if as := s.m.Assets(); as != nil {
		for _, ty := range []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"} {
			ns, _ := as.QueryByType(ty, 100000, 0)
			if len(ns) > 0 {
				counts[ty] = len(ns)
			}
			for _, a := range ns {
				if a == nil {
					continue
				}
				lbl := assetLabel(a)
				assetLabels[a.ID] = lbl
				if len(assetEntries) < 200 {
					host := a.Domain
					if host == "" {
						host = a.IP
					}
					if host == "" {
						host = a.RootDomain
					}
					extra := strings.Join(a.Technologies, ", ")
					if a.ServiceName != "" && extra != "" {
						extra = a.ServiceName + " (" + extra + ")"
					} else if a.ServiceName != "" {
						extra = a.ServiceName
					}
					assetEntries = append(assetEntries, report.AssetEntry{
						ID:    a.ID,
						Type:  a.Type,
						Label: lbl,
						Host:  host,
						Extra: extra,
					})
				}
			}
		}
	}

	var intelItems []*db.Intelligence
	if taskID > 0 {
		if page, err := s.m.pg.ListIntelligence(ctx, db.IntelligenceFilter{TaskID: taskID, Limit: 100}); err == nil && page != nil {
			intelItems = page.Items
		}
	}

	artifacts := s.collectTaskReportArtifacts(t.ID, intentTitles)

	title := strings.TrimSpace(t.Name)
	if title == "" {
		title = t.Description
	}
	var createdAt time.Time
	if t.CreatedAt > 0 {
		createdAt = time.Unix(t.CreatedAt, 0)
	}
	var completedAt *time.Time
	if t.CompletedAt > 0 {
		ct := time.Unix(t.CompletedAt, 0)
		completedAt = &ct
	}

	return report.Markdown(report.Input{
		TaskID:        t.ID,
		Title:         title,
		Goal:          t.Goal,
		Status:        s.deriveTaskStatus(t),
		Scope:         scopeVals,
		CreatedAt:     createdAt,
		CompletedAt:   completedAt,
		GeneratedAt:   time.Now(),
		AssetCounts:   counts,
		Assets:        assetEntries,
		AssetLabels:   assetLabels,
		Constraints:   constraints,
		Hints:         hints,
		Goals:         goals,
		Edges:         edges,
		Intents:       intents,
		Facts:         facts,
		Findings:      findings,
		DBFindings:    dbFindings,
		FindingChains: findingChains,
		Intelligence:  intelItems,
		Artifacts:     artifacts,
	})
}

func (s *Server) collectTaskReportArtifacts(taskID string, intentTitles map[int64]string) []report.ArtifactFile {
	taskDir := filepath.Join(s.m.dir, "tasks", taskID)
	info, err := os.Stat(taskDir)
	if err != nil || !info.IsDir() {
		return nil
	}
	var out []report.ArtifactFile
	_ = filepath.WalkDir(taskDir, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		if len(out) >= 100 {
			return filepath.SkipAll
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(taskDir, p)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		var intentID int64
		parts := strings.Split(relSlash, "/")
		if len(parts) > 0 && strings.HasPrefix(parts[0], "i") {
			if id, err := strconv.ParseInt(strings.TrimPrefix(parts[0], "i"), 10, 64); err == nil && id > 0 {
				intentID = id
			}
		}
		var preview string
		ext := strings.ToLower(filepath.Ext(relSlash))
		switch ext {
		case ".py", ".sh", ".txt", ".md", ".json", ".yaml", ".yml", ".http", ".sql", ".js", ".go", ".xml", ".conf":
			if fi.Size() > 0 && fi.Size() <= 16384 {
				if raw, err := os.ReadFile(p); err == nil {
					text := strings.TrimSpace(string(raw))
					if len(text) > 2000 {
						text = text[:2000] + "\n...[truncated]..."
					}
					preview = text
				}
			}
		}
		out = append(out, report.ArtifactFile{
			Path:        relSlash,
			Size:        fi.Size(),
			ModTime:     fi.ModTime(),
			IntentID:    intentID,
			IntentTitle: intentTitles[intentID],
			Preview:     preview,
		})
		return nil
	})
	return out
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeJSON(w, 200, []any{})
		return
	}
	writeJSON(w, 200, map[string]any{"entries": t.Guard.Audit(), "attributions": t.Guard.Attributions()})
}

// gc is a no-op stub (GC not yet implemented in the new asset store).
func (s *Server) gc(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"removed": 0})
}

// --- utils ---

func isLoopbackHost(h string) bool {
	return strings.EqualFold(h, "localhost") || h == "127.0.0.1" || h == "::1"
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// Allow credentials only when the Origin matches the request Host, or when BOTH
		// Origin and Host are loopback addresses (e.g. localhost:3000 -> 127.0.0.1:8787).
		origin := r.Header.Get("Origin")
		u, err := url.Parse(origin)
		host, _, hostErr := net.SplitHostPort(r.Host)
		if hostErr != nil {
			host = r.Host
		}
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" &&
			(strings.EqualFold(u.Hostname(), host) || (isLoopbackHost(u.Hostname()) && isLoopbackHost(host))) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Add("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		exposeHeaders := "X-Behemoth-Auth"
		if dynamicAuthHeaderName != "" && !strings.EqualFold(dynamicAuthHeaderName, "X-Behemoth-Auth") {
			exposeHeaders += ", " + dynamicAuthHeaderName
		}
		w.Header().Set("Access-Control-Expose-Headers", exposeHeaders)
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// === PROXY POOL V2 INTEGRATION ===

// proxyPoolV2 holds the v2 proxy pool components (initialized once at startup).
type proxyPoolV2 struct {
	Pool       *proxyv2.Pool
	Store      *proxyv2.PGStore
	Handler    *proxyv2.Handler
	Middleware *proxyv2.Middleware
}

// ppV2 is the global Proxy Pool v2 instance, nil until initialized.
var ppV2 *proxyPoolV2

// GetProxyPoolV2 returns the global Proxy Pool v2 instance (nil if not initialized).
func GetProxyPoolV2() *proxyPoolV2 {
	return ppV2
}

// initProxyPoolV2 initializes the Proxy Pool v2 system with PostgreSQL backend.
// Called once during Server.New() if DB is available.
func (s *Server) initProxyPoolV2(m *Manager) {
	// db.DB embeds *sql.DB, so we can pass it directly
	store := proxyv2.NewPGStore(m.pg.DB)
	if err := store.InitTable(context.Background()); err != nil {
		log.Printf("[proxy-v2] Warning: proxy pool table init error: %v", err)
	}
	pool := proxyv2.NewPool(store)
	if err := pool.Initialize(); err != nil {
		log.Printf("[proxy-v2] Warning: proxy pool init error: %v", err)
	}
	handler := proxyv2.NewHandler(pool)
	middleware := proxyv2.NewMiddleware(pool)

	ppV2 = &proxyPoolV2{
		Pool:       pool,
		Store:      store,
		Handler:    handler,
		Middleware: middleware,
	}

	rawV2, activeV2, cfgV2 := pool.GetRawState()
	v1Entries := m.proxyPoolEntries()
	if len(rawV2) > 0 && len(v1Entries) == 0 {
		s.syncProxyPoolV2ToV1(rawV2, activeV2, cfgV2)
	} else if len(v1Entries) > 0 && len(rawV2) == 0 {
		s.syncV1ToProxyPoolV2()
	}

	pool.SetSyncHook(func(proxies []proxyv2.ProxyInfo, activeID string, cfg *proxyv2.ProxyPoolConfig) {
		s.syncProxyPoolV2ToV1(proxies, activeID, cfg)
	})

	proxies := pool.GetProxies()
	log.Printf("[proxy-v2] Proxy Pool v2 initialized and unified with core agent proxy engine (%d proxies)", len(proxies))
	s.restorePersistedTorOnBoot()
}

var proxyV2SyncMu sync.Mutex

func (s *Server) syncProxyPoolV2ToV1(proxies []proxyv2.ProxyInfo, activeID string, cfg *proxyv2.ProxyPoolConfig) {
	if s == nil || s.m == nil {
		return
	}
	proxyV2SyncMu.Lock()
	defer proxyV2SyncMu.Unlock()
	if ppV2 != nil && ppV2.Pool != nil {
		proxies, activeID, cfg = ppV2.Pool.GetRawState()
	}
	poolEnabled := cfg != nil && cfg.Enabled
	if poolEnabled && s.isExclusiveTorActive() {
		log.Printf("[tor] Proxy Pool switched ON while Exclusive Tor was active — shutting down Exclusive Tor daemon")
		s.shutdownExclusiveTor()
	} else if !poolEnabled && !s.isExclusiveTorActive() {
		// If Pool Active was turned OFF while Hybrid Tor circuits were inside the pool,
		// remove the Hybrid Tor circuits and stop the Tor daemon cleanly!
		hasHybridTor := false
		for _, px := range proxies {
			if strings.HasPrefix(px.ID, torManagedPrefix) {
				hasHybridTor = true
				break
			}
		}
		if hasHybridTor && ppV2 != nil && ppV2.Pool != nil {
			go s.shutdownHybridTorIfPoolDisabled()
		}
	}
	s.m.SetProxyPoolFailClosed(poolEnabled)
	entries := make([]proxyPoolEntry, 0, len(proxies))
	if poolEnabled {
		for _, px := range proxies {
			rawURL := px.BuildProxyURL()
			enabled := px.Active && px.Status != proxyv2.StatusDisabled
			health := "unknown"
			switch px.Status {
			case proxyv2.StatusHealthy, proxyv2.StatusInUse:
				health = "healthy"
			case proxyv2.StatusUnhealthy, proxyv2.StatusUnhealthyCool:
				health = "unhealthy-cooling"
			case proxyv2.StatusDisabled:
				health = "disabled"
			}
			entries = append(entries, proxyPoolEntry{
				ProxyPoolEntry: ProxyPoolEntry{
					ID:                  px.ID,
					URL:                 maskSecrets(rawURL),
					Name:                px.Name,
					Remark:              px.Notes,
					Enabled:             enabled,
					EgressIP:            px.ResponseIP,
					LatencyMS:           px.Latency.Milliseconds(),
					LastCheckedAt:       px.LastChecked,
					ConsecutiveFailures: px.ConsecutiveFailures,
					Health:              health,
				},
				RawURL: rawURL,
			})
		}
	}
	effectiveActive := ""
	if poolEnabled {
		for _, px := range proxies {
			if px.ID == activeID && px.Active && px.Status != proxyv2.StatusDisabled && px.Status != proxyv2.StatusUnhealthy && px.Status != proxyv2.StatusUnhealthyCool {
				effectiveActive = activeID
				break
			}
		}
	}
	_ = s.m.setProxyPoolEntries(entries, effectiveActive)
	if poolEnabled && effectiveActive == "" {
		// Fail-closed: Proxy Pool is enabled, and zero healthy proxies are usable.
		// Immediately pause running tasks and stop active chat scans so agents never
		// continue unproxied or spin on failed connections.
		s.pauseAllProxyTasks(errors.New("Proxy Pool is enabled, and all configured proxies are unhealthy or out of bandwidth — tasks paused to prevent direct IP exposure"))
		s.stopActiveChatsOnProxyExhausted()
	} else if poolEnabled && effectiveActive != "" {
		s.proxyReconnectSuccess()
	}
	if cfg != nil {
		strategy := "sequential"
		switch cfg.RotationMode {
		case proxyv2.RotationRandom:
			strategy = "random"
		case proxyv2.RotationLeastUsed:
			strategy = "least_used"
		}
		interval := cfg.RotationIntervalSeconds
		if interval < minProxyRotateInterval {
			interval = defaultProxyRotateInterval
		}
		threshold := cfg.MaxConsecutiveFailures
		if threshold < 1 {
			threshold = defaultProxyHealthThreshold
		}
		cooldown := cfg.CooldownSeconds
		if cooldown < 1 {
			cooldown = defaultProxyHealthCooldown
		}
		healthInt := cfg.HealthCheckIntervalSeconds
		if healthInt < 1 {
			healthInt = defaultProxyHealthInterval
		}
		// When SessionSticky is enabled, keep the active proxy sticky across requests
		// and rotate only on failure (or manual/agent rotate); when SessionSticky is
		// false, also rotate automatically on the configured timer interval.
		timedRotate := poolEnabled && !cfg.SessionSticky
		_ = s.m.SetProxyPoolSettings(timedRotate, interval, poolEnabled && (cfg.AutoRotateOnFailure || cfg.FailoverEnabled), strategy, threshold, cooldown, healthInt)
	}
	if poolEnabled && s.proxyPoolWake != nil {
		select {
		case s.proxyPoolWake <- struct{}{}:
		default:
		}
	}
	s.profMu.Lock()
	s.profChatAgents = map[int64]*agent.ChatAgent{}
	s.profMu.Unlock()
	if s.chatAgent != nil {
		s.chatAgent.SetWebSearch(s.m.WebSearchOpts())
	}
}

func (s *Server) syncV1ToProxyPoolV2() {
	if s == nil || s.m == nil || ppV2 == nil || ppV2.Pool == nil {
		return
	}
	existing, _, _ := ppV2.Pool.GetRawState()
	byID := map[string]proxyv2.ProxyInfo{}
	for _, px := range existing {
		byID[px.ID] = px
	}
	v1Entries := s.m.proxyPoolEntries()
	v2List := make([]proxyv2.ProxyInfo, 0, len(v1Entries))
	for _, e := range v1Entries {
		u, err := url.Parse(e.RawURL)
		if err != nil || u.Host == "" {
			continue
		}
		host, portStr, splitErr := net.SplitHostPort(u.Host)
		if splitErr != nil {
			host = u.Hostname()
			portStr = u.Port()
		}
		port, _ := strconv.Atoi(portStr)
		if port <= 0 {
			continue
		}
		pass, _ := u.User.Password()
		prev := byID[e.ID]
		status := proxyv2.StatusUntested
		switch e.Health {
		case "healthy":
			status = proxyv2.StatusHealthy
		case "unhealthy-cooling", "unhealthy":
			status = proxyv2.StatusUnhealthy
		case "disabled":
			status = proxyv2.StatusDisabled
		}
		if !e.Enabled {
			status = proxyv2.StatusDisabled
		}
		v2List = append(v2List, proxyv2.ProxyInfo{
			ID:                  e.ID,
			Type:                proxyv2.ProxyType(strings.ToLower(u.Scheme)),
			Host:                host,
			Port:                port,
			Username:            u.User.Username(),
			Password:            pass,
			Country:             prev.Country,
			City:                prev.City,
			Status:              status,
			Active:              e.Enabled,
			LastChecked:         e.LastCheckedAt,
			SuccessRate:         prev.SuccessRate,
			Latency:             time.Duration(e.LatencyMS) * time.Millisecond,
			LatencyMS:           e.LatencyMS,
			ConsecutiveFailures: e.ConsecutiveFailures,
			ResponseIP:          e.EgressIP,
			Name:                e.Name,
			Notes:               e.Remark,
			CreatedAt:           prev.CreatedAt,
			UpdatedAt:           time.Now(),
		})
	}
	_ = ppV2.Pool.SyncFromExternal(v2List, s.m.proxyPoolActiveID())
}

// stopActiveChatsOnProxyExhausted aborts in-flight interactive/task chat runs
// with AbortPausedByProxy whenever Proxy Pool is enabled and all proxies go down,
// EXCEPT proxy_harvester runs so the harvester can discover/verify replacement proxies!
func (s *Server) stopActiveChatsOnProxyExhausted() {
	if s == nil {
		return
	}
	s.chatMu.Lock()
	keys := make([]string, 0, len(s.chatCancel))
	cancels := make([]context.CancelCauseFunc, 0, len(s.chatCancel))
	for k, cancel := range s.chatCancel {
		if cancel != nil {
			keys = append(keys, k)
			cancels = append(cancels, cancel)
		}
	}
	s.chatMu.Unlock()
	for i, cancel := range cancels {
		k := keys[i]
		if strings.HasPrefix(k, "conv-") && s.m != nil && s.m.pg != nil {
			if cid, err := strconv.ParseInt(strings.TrimPrefix(k, "conv-"), 10, 64); err == nil {
				if conv, gerr := s.m.pg.GetConversation(cid); gerr == nil && conv != nil && conv.AgentKey == "proxy_harvester" {
					continue
				}
			}
		}
		cancel(agent.AbortPausedByProxy)
	}
}

// registerProxyPoolV2Routes registers all v2 API endpoints on the given mux.
func (s *Server) registerProxyPoolV2Routes(mux *http.ServeMux) {
	if ppV2 == nil || ppV2.Handler == nil {
		return
	}
	ppV2.Handler.RegisterRoutes(mux)
	mux.HandleFunc("GET /api/v2/proxy-pool/tor/status", s.handleTorStatus)
	mux.HandleFunc("POST /api/v2/proxy-pool/tor/enable", s.handleTorEnable)
	mux.HandleFunc("POST /api/v2/proxy-pool/tor/disable", s.handleTorDisable)
	mux.HandleFunc("POST /api/v2/proxy-pool/tor/newnym", s.handleTorNewnym)
	mux.HandleFunc("GET /api/v2/proxy-pool/scraper/status", s.handleScraperStatus)
	mux.HandleFunc("PUT /api/v2/proxy-pool/scraper/config", s.handleScraperSaveConfig)
	mux.HandleFunc("POST /api/v2/proxy-pool/scraper/run", s.handleScraperRunNow)
	mux.HandleFunc("POST /api/v2/proxy-pool/scraper/run-agent", s.handleScraperRunAgent)
	mux.HandleFunc("POST /api/v2/proxy-pool/scraper/stop", s.handleScraperStop)
	mux.HandleFunc("POST /api/v2/proxy-pool/scraper/clear", s.handleScraperClear)
	log.Printf("[proxy-v2] Registered API endpoints under /api/v2/proxy-pool/")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func atoiDefault(s string, d int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return d
}

// ============================================================
// TOOL RECIPES API HANDLERS (CyberStrikeAI-style)
// ============================================================

func (s *Server) handleListRecipes(w http.ResponseWriter, r *http.Request) {
	if s.recipeReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "recipe registry not initialized")
		return
	}
	recipes := s.recipeReg.List()
	writeJSON(w, http.StatusOK, map[string]any{
		"recipes": recipes,
		"count":   len(recipes),
	})
}

func (s *Server) handleGetRecipe(w http.ResponseWriter, r *http.Request) {
	if s.recipeReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "recipe registry not initialized")
		return
	}
	id := r.PathValue("id")
	recipe, ok := s.recipeReg.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("recipe not found: %s", id))
		return
	}
	writeJSON(w, http.StatusOK, recipe)
}

func (s *Server) handleRecipeCategories(w http.ResponseWriter, r *http.Request) {
	if s.recipeReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "recipe registry not initialized")
		return
	}
	categories := s.recipeReg.Categories()
	writeJSON(w, http.StatusOK, map[string]any{
		"categories": categories,
		"count":      len(categories),
	})
}

func (s *Server) handleSearchRecipes(w http.ResponseWriter, r *http.Request) {
	if s.recipeReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "recipe registry not initialized")
		return
	}
	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	results := s.recipeReg.Search(req.Query)
	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"query":   req.Query,
		"count":   len(results),
	})
}

// ============================================================
// FACT GRAPH API HANDLERS (sapper-v2 style)
// ============================================================

func (s *Server) handleListFacts(w http.ResponseWriter, r *http.Request) {
	if s.factGraph == nil {
		writeErr(w, http.StatusServiceUnavailable, "fact graph not initialized")
		return
	}
	facts := s.factGraph.List()
	writeJSON(w, http.StatusOK, map[string]any{
		"facts": facts,
		"count": len(facts),
	})
}

func (s *Server) handleCreateFact(w http.ResponseWriter, r *http.Request) {
	if s.factGraph == nil {
		writeErr(w, http.StatusServiceUnavailable, "fact graph not initialized")
		return
	}
	var req struct {
		Kind       string            `json:"kind"`
		Title      string            `json:"title"`
		Content    string            `json:"content"`
		TaskID     string            `json:"task_id,omitempty"`
		SessionID  string            `json:"session_id,omitempty"`
		Metadata   map[string]string `json:"metadata,omitempty"`
		Tags       []string          `json:"tags,omitempty"`
		Confidence float64           `json:"confidence"`
		Agent      string            `json:"agent,omitempty"`
		Method     string            `json:"method,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	fact := factgraph.NewFact(factgraph.FactKind(req.Kind), req.Title, req.Content)
	fact.TaskID = req.TaskID
	fact.SessionID = req.SessionID
	if req.Metadata != nil {
		fact.Metadata = req.Metadata
	}
	if req.Tags != nil {
		fact.Tags = req.Tags
	}
	if req.Confidence > 0 {
		fact.Confidence = req.Confidence
	}
	fact.Agent = req.Agent
	fact.Method = req.Method

	s.factGraph.Add(fact)
	log.Printf("[factgraph] Created fact: %s (%s)", fact.ID, fact.Kind)
	writeJSON(w, http.StatusCreated, fact)
}

func (s *Server) handleGetFact(w http.ResponseWriter, r *http.Request) {
	if s.factGraph == nil {
		writeErr(w, http.StatusServiceUnavailable, "fact graph not initialized")
		return
	}
	id := r.PathValue("id")
	fact, ok := s.factGraph.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("fact not found: %s", id))
		return
	}
	writeJSON(w, http.StatusOK, fact)
}

func (s *Server) handleUpdateFact(w http.ResponseWriter, r *http.Request) {
	if s.factGraph == nil {
		writeErr(w, http.StatusServiceUnavailable, "fact graph not initialized")
		return
	}
	id := r.PathValue("id")
	var req struct {
		Title      *string           `json:"title,omitempty"`
		Content    *string           `json:"content,omitempty"`
		Tags       *[]string         `json:"tags,omitempty"`
		Confidence *float64          `json:"confidence,omitempty"`
		Verified   *bool             `json:"verified,omitempty"`
		Active     *bool             `json:"active,omitempty"`
		Metadata   map[string]string `json:"metadata,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err := s.factGraph.Update(id, func(f *factgraph.Fact) {
		if req.Title != nil {
			f.Title = *req.Title
		}
		if req.Content != nil {
			f.Content = *req.Content
		}
		if req.Tags != nil {
			f.Tags = *req.Tags
		}
		if req.Confidence != nil {
			f.Confidence = *req.Confidence
		}
		if req.Verified != nil {
			f.Verified = *req.Verified
		}
		if req.Active != nil {
			f.Active = *req.Active
		}
		if req.Metadata != nil {
			f.Metadata = req.Metadata
		}
	})
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	fact, _ := s.factGraph.Get(id)
	writeJSON(w, http.StatusOK, fact)
}

func (s *Server) handleDeleteFact(w http.ResponseWriter, r *http.Request) {
	if s.factGraph == nil {
		writeErr(w, http.StatusServiceUnavailable, "fact graph not initialized")
		return
	}
	id := r.PathValue("id")
	s.factGraph.Remove(id)
	writeJSON(w, http.StatusOK, map[string]any{"message": "fact deleted", "id": id})
}

func (s *Server) handleSearchFacts(w http.ResponseWriter, r *http.Request) {
	if s.factGraph == nil {
		writeErr(w, http.StatusServiceUnavailable, "fact graph not initialized")
		return
	}
	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	results := s.factGraph.Search(req.Query)
	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"query":   req.Query,
		"count":   len(results),
	})
}

func (s *Server) handleFactStats(w http.ResponseWriter, r *http.Request) {
	if s.factGraph == nil {
		writeErr(w, http.StatusServiceUnavailable, "fact graph not initialized")
		return
	}
	stats := s.factGraph.Stats()
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleLinkFacts(w http.ResponseWriter, r *http.Request) {
	if s.factGraph == nil {
		writeErr(w, http.StatusServiceUnavailable, "fact graph not initialized")
		return
	}
	var req struct {
		SourceID string `json:"source_id"`
		TargetID string `json:"target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.factGraph.Link(req.SourceID, req.TargetID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":   "facts linked",
		"source_id": req.SourceID,
		"target_id": req.TargetID,
	})
}

// ============================================================
// TLS FINGERPRINTING API HANDLERS
// ============================================================

func (s *Server) handleTLSSpecs(w http.ResponseWriter, r *http.Request) {
	specs := fingerprint.GetAllTLSSpecs()
	result := make([]map[string]string, len(specs))
	for i, spec := range specs {
		result[i] = map[string]string{
			"id":          spec.ID,
			"name":        spec.Name,
			"description": spec.Description,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"specs": result,
		"count": len(result),
	})
}

func (s *Server) handleTLSCurrent(w http.ResponseWriter, r *http.Request) {
	spec := fingerprint.GetTLSSpec("chrome_120")
	writeJSON(w, http.StatusOK, map[string]string{
		"id":          spec.ID,
		"name":        spec.Name,
		"description": spec.Description,
	})
}

// ============================================================
// TOOL CATALOG & EXECUTION API HANDLERS
// ============================================================

func (s *Server) handleListTools(w http.ResponseWriter, r *http.Request) {
	if s.toolCatalog == nil {
		writeErr(w, http.StatusServiceUnavailable, "tool catalog not initialized")
		return
	}
	tools := s.toolCatalog.List()
	writeJSON(w, http.StatusOK, map[string]any{"tools": tools, "count": len(tools)})
}

func (s *Server) handleGetTool(w http.ResponseWriter, r *http.Request) {
	if s.toolCatalog == nil {
		writeErr(w, http.StatusServiceUnavailable, "tool catalog not initialized")
		return
	}
	id := r.PathValue("id")
	tool, ok := s.toolCatalog.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "tool not found")
		return
	}
	writeJSON(w, http.StatusOK, tool)
}

func (s *Server) handleToolCategories(w http.ResponseWriter, r *http.Request) {
	if s.toolCatalog == nil {
		writeErr(w, http.StatusServiceUnavailable, "tool catalog not initialized")
		return
	}
	cats := s.toolCatalog.Categories()
	writeJSON(w, http.StatusOK, map[string]any{"categories": cats, "count": len(cats)})
}

func (s *Server) handleSearchTools(w http.ResponseWriter, r *http.Request) {
	if s.toolCatalog == nil {
		writeErr(w, http.StatusServiceUnavailable, "tool catalog not initialized")
		return
	}
	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	results := s.toolCatalog.Search(req.Query)
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "count": len(results)})
}

func (s *Server) handleExecuteTool(w http.ResponseWriter, r *http.Request) {
	if s.toolExecutor == nil {
		writeErr(w, http.StatusServiceUnavailable, "tool executor not initialized")
		return
	}
	var req struct {
		ToolID     string            `json:"tool_id"`
		Parameters map[string]string `json:"parameters"`
		Timeout    int               `json:"timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	execution, err := s.toolExecutor.Execute(r.Context(), req.ToolID, req.Parameters)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	parsed := tools.ParseToolOutput(req.ToolID, execution.Output)
	writeJSON(w, http.StatusOK, map[string]any{
		"execution_id": execution.ID,
		"tool_id":      execution.ToolID,
		"status":       execution.Status,
		"output":       execution.Output,
		"parsed":       parsed,
		"duration":     execution.Duration.String(),
		"exit_code":    execution.ExitCode,
	})
}

func (s *Server) handleGetExecution(w http.ResponseWriter, r *http.Request) {
	if s.toolExecutor == nil {
		writeErr(w, http.StatusServiceUnavailable, "tool executor not initialized")
		return
	}
	id := r.PathValue("id")
	execution, ok := s.toolExecutor.GetExecution(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "execution not found")
		return
	}
	writeJSON(w, http.StatusOK, execution)
}

func (s *Server) handleExecutionHistory(w http.ResponseWriter, r *http.Request) {
	if s.toolExecutor == nil {
		writeErr(w, http.StatusServiceUnavailable, "tool executor not initialized")
		return
	}
	history := s.toolExecutor.History(100)
	writeJSON(w, http.StatusOK, map[string]any{"history": history, "count": len(history)})
}

// ============================================================
// TARGET CONNECTORS API HANDLERS
// ============================================================

func (s *Server) handleConnectSSH(w http.ResponseWriter, r *http.Request) {
	var req targets.SSHConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	connector, err := targets.NewSSHConnector(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := connector.Connect(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "SSH connection failed: "+err.Error())
		return
	}
	targetID := fmt.Sprintf("ssh-%s-%d", req.Host, req.Port)
	s.targetMu.Lock()
	s.targets[targetID] = connector
	s.targetMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"target_id": targetID, "type": "ssh",
		"host": req.Host, "port": req.Port,
		"user": req.User, "connected": true,
	})
}

func (s *Server) handleConnectWinRM(w http.ResponseWriter, r *http.Request) {
	var req targets.WinRMConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	connector, err := targets.NewWinRMConnector(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := connector.Connect(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "WinRM connection failed: "+err.Error())
		return
	}
	targetID := fmt.Sprintf("winrm-%s-%d", req.Host, req.Port)
	s.targetMu.Lock()
	s.targets[targetID] = connector
	s.targetMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"target_id": targetID, "type": "winrm",
		"host": req.Host, "port": req.Port,
		"user": req.User, "connected": true,
	})
}

func (s *Server) handleDisconnectTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.targetMu.Lock()
	connector, ok := s.targets[id]
	if !ok {
		s.targetMu.Unlock()
		writeErr(w, http.StatusNotFound, "target not connected")
		return
	}
	delete(s.targets, id)
	s.targetMu.Unlock()
	connector.Close()
	writeJSON(w, http.StatusOK, map[string]any{"message": "disconnected", "target_id": id})
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	s.targetMu.Lock()
	defer s.targetMu.Unlock()
	result := make([]map[string]interface{}, 0, len(s.targets))
	for id, conn := range s.targets {
		t := conn.Target()
		result = append(result, map[string]interface{}{
			"id": id, "type": t.Type, "host": t.Host,
			"port": t.Port, "user": t.User,
			"connected": conn.IsConnected(), "labels": t.Labels,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": result, "count": len(result)})
}

func (s *Server) handleTargetExecute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.targetMu.Lock()
	connector, ok := s.targets[id]
	s.targetMu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "target not connected")
		return
	}
	var req struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := connector.Execute(r.Context(), req.Command)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "execution failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target_id": id, "command": req.Command,
		"stdout": result.Stdout, "stderr": result.Stderr,
		"exit_code": result.ExitCode, "duration": result.Duration.String(),
	})
}

func (s *Server) handleSFTPUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.targetMu.Lock()
	connector, ok := s.targets[id]
	s.targetMu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "target not connected")
		return
	}
	sshConn, ok := connector.(*targets.SSHConnector)
	if !ok {
		writeErr(w, http.StatusBadRequest, "SFTP only available for SSH targets")
		return
	}
	var req struct {
		LocalPath  string `json:"local_path"`
		RemotePath string `json:"remote_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	session, err := sshConn.NewSFTPSession()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SFTP error: "+err.Error())
		return
	}
	defer session.Close()
	if err := session.UploadFile(req.LocalPath, req.RemotePath); err != nil {
		writeErr(w, http.StatusInternalServerError, "upload failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "uploaded", "local": req.LocalPath, "remote": req.RemotePath})
}

func (s *Server) handleSFTPDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.targetMu.Lock()
	connector, ok := s.targets[id]
	s.targetMu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "target not connected")
		return
	}
	sshConn, ok := connector.(*targets.SSHConnector)
	if !ok {
		writeErr(w, http.StatusBadRequest, "SFTP only available for SSH targets")
		return
	}
	var req struct {
		RemotePath string `json:"remote_path"`
		LocalPath  string `json:"local_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	session, err := sshConn.NewSFTPSession()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SFTP error: "+err.Error())
		return
	}
	defer session.Close()
	if err := session.DownloadFile(req.RemotePath, req.LocalPath); err != nil {
		writeErr(w, http.StatusInternalServerError, "download failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "downloaded", "remote": req.RemotePath, "local": req.LocalPath})
}

// ============================================================
// SECURITY MIDDLEWARE & HANDLERS
// ============================================================

// securityMiddleware applies IOC blocking, anti-bot checks, and backdoor detection
func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip security check for health/version/auth endpoints (they're public)
		path := r.URL.Path
		if path == "/api/health" || path == "/api/version" ||
			path == "/api/update/maintenance" || path == "/api/update/webhook" ||
			strings.HasPrefix(path, "/api/auth/") || strings.HasPrefix(path, "/api/oast-cb/") || strings.HasPrefix(path, "/api/c2/") || strings.HasPrefix(path, "/c2/ui/") || path == "/api/basic-auth/check" {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := getClientIP(r)
		isLoopback := clientIP == "127.0.0.1" || clientIP == "::1" || clientIP == "localhost"
		hasAuth := r.Header.Get("Authorization") != ""
		if !hasAuth {
			for _, c := range r.Cookies() {
				if strings.TrimSpace(c.Value) != "" {
					hasAuth = true
					break
				}
			}
		}

		// 1. IOC Blocklist Check
		// Always block known malicious IOC IPs; only apply heuristic URL/UA scanner scoring
		// to unauthenticated requests so authenticated operators using Repeater/Search/Chat
		// with exploit payloads are never falsely blocked.
		if s.iocBlocklist != nil && !isLoopback {
			if hasAuth {
				if blocked, ip := s.iocBlocklist.IsBlockedIP(r); blocked {
					log.Printf("[security] BLOCKED by IOC IP: IP=%s", ip)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]any{
						"error":  "request blocked",
						"reason": "IOC_IP_BLOCKED",
						"score":  100,
					})
					return
				}
			} else {
				result := s.iocBlocklist.CheckRequest(r)
				if !result.Allowed {
					log.Printf("[security] BLOCKED by IOC/Scanner filter: IP=%s Flags=%v Score=%d",
						clientIP, result.Flags, result.ThreatScore)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]any{
						"error":  "request blocked",
						"reason": result.BlockReason,
						"score":  result.ThreatScore,
					})
					return
				}
			}
		}

		// 2. Rate Limit Check (Anti-Detect)
		if s.antiDetect != nil && !isLoopback && !hasAuth {
			allowed, wait := s.antiDetect.CheckRateLimit(clientIP)
			if !allowed {
				log.Printf("[security] RATE LIMITED: IP=%s Wait=%v", clientIP, wait)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", wait.Seconds()))
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]any{
					"error":       "rate limited",
					"retry_after": wait.Seconds(),
				})
				return
			}
		}

		// 3. Backdoor Detection (for POST requests)
		if s.backdoorDetector != nil && r.Method == "POST" {
			bdResult := s.backdoorDetector.CheckRequest(r)
			if bdResult.Suspicious {
				log.Printf("[security] BACKDOOR PATTERN DETECTED: IP=%s Patterns=%v",
					getClientIP(r), bdResult.Patterns)
				// Log but don't block - could be false positive
				// In production, you might want to block or require CAPTCHA
			}

			// Also check body for backdoor patterns
			body, err := security.ReadBody(r)
			if err == nil && len(body) > 0 {
				bodyResult := s.backdoorDetector.CheckBody(body, r.URL.Path)
				if bodyResult.Suspicious {
					log.Printf("[security] SUSPICIOUS BODY: IP=%s Path=%s Patterns=%v",
						getClientIP(r), r.URL.Path, bodyResult.Patterns)
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts client IP from request (supports X-Forwarded-For, X-Real-IP)
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// handleSecurityStats returns security statistics
func (s *Server) handleSecurityStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]any{
		"ioc_blocklist":              s.iocBlocklist.GetStats(),
		"stealth_enabled":            s.antiDetect != nil,
		"backdoor_detection_enabled": s.backdoorDetector != nil,
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleListIOCs returns list of blocked IPs
func (s *Server) handleListIOCs(w http.ResponseWriter, r *http.Request) {
	stats := s.iocBlocklist.GetStats()
	blocked := stats.BlockedIPs
	if blocked == nil {
		blocked = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"blocked_ips":   blocked,
		"total_blocked": len(blocked),
	})
}

// handleAddIOC adds an IP to the blocklist
func (s *Server) handleAddIOC(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.IP == "" {
		writeErr(w, http.StatusBadRequest, "ip is required")
		return
	}
	s.iocBlocklist.AddBlockedIP(req.IP, req.Reason)
	if s.m != nil && s.m.pg != nil {
		if b, err := json.Marshal(s.iocBlocklist.GetStats().BlockedIPs); err == nil {
			_ = s.m.pg.SetSetting("security_ioc_blocked_ips", string(b))
		}
	}
	log.Printf("[security] IOC added: IP=%s Reason=%s", req.IP, req.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"message": "ip blocked", "ip": req.IP})
}

// handleRemoveIOC removes an IP from the blocklist
func (s *Server) handleRemoveIOC(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		writeErr(w, http.StatusBadRequest, "ip is required")
		return
	}
	s.iocBlocklist.RemoveBlockedIP(ip)
	if s.m != nil && s.m.pg != nil {
		if b, err := json.Marshal(s.iocBlocklist.GetStats().BlockedIPs); err == nil {
			_ = s.m.pg.SetSetting("security_ioc_blocked_ips", string(b))
		}
	}
	log.Printf("[security] IOC removed: IP=%s", ip)
	writeJSON(w, http.StatusOK, map[string]any{"message": "ip unblocked", "ip": ip})
}

// handleSecurityCheck performs a full security check on a request
func (s *Server) handleSecurityCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL      string            `json:"url"`
		Method   string            `json:"method"`
		Headers  map[string]string `json:"headers"`
		Body     string            `json:"body"`
		UA       string            `json:"user_agent"`
		ClientIP string            `json:"client_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Create mock request for testing
	testURL, _ := url.Parse(req.URL)
	testReq := &http.Request{
		Method: req.Method,
		URL:    testURL,
		Header: make(http.Header),
	}
	for k, v := range req.Headers {
		testReq.Header.Set(k, v)
	}
	if req.UA != "" {
		testReq.Header.Set("User-Agent", req.UA)
	}
	if req.ClientIP != "" {
		testReq.RemoteAddr = req.ClientIP + ":12345"
	}

	results := map[string]any{}

	// Run IOC check
	iocResult := s.iocBlocklist.CheckRequest(testReq)
	results["ioc_check"] = iocResult

	// Run backdoor check
	bdResult := s.backdoorDetector.CheckRequest(testReq)
	if req.Body != "" && req.Method == "POST" {
		bodyResult := s.backdoorDetector.CheckBody([]byte(req.Body), req.URL)
		results["backdoor_body_check"] = bodyResult
	}
	results["backdoor_check"] = bdResult

	writeJSON(w, http.StatusOK, results)
}

// handleGetStealthConfig returns current stealth/anti-detect configuration
func (s *Server) handleGetStealthConfig(w http.ResponseWriter, r *http.Request) {
	if s.antiDetect == nil {
		writeErr(w, http.StatusServiceUnavailable, "anti-detect not initialized")
		return
	}
	writeJSON(w, http.StatusOK, s.antiDetect.GetConfig())
}

// handleUpdateStealthConfig updates stealth/anti-detect configuration
func (s *Server) handleUpdateStealthConfig(w http.ResponseWriter, r *http.Request) {
	var cfg security.StealthConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 120
	}
	// Reinitialize anti-detect with new config
	s.antiDetect = security.NewAntiDetect(cfg)
	if s.m != nil && s.m.pg != nil {
		if b, err := json.Marshal(cfg); err == nil {
			_ = s.m.pg.SetSetting("security_stealth_config", string(b))
		}
	}
	log.Printf("[security] Stealth config updated: enabled=%v", cfg.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"message": "config updated", "config": cfg})
}

// ==================== Multi-Engine Web Search Handlers (Pentagi-inspired) ====================

// SearchRequest is the JSON request for search API.
type SearchRequest struct {
	Query      string `json:"query"`
	Mode       string `json:"mode,omitempty"`   // general, news, exploit, technical, osint
	Engine     string `json:"engine,omitempty"` // optional specific engine to test/query
	MaxResults int    `json:"max_results,omitempty"`
	SiteFilter string `json:"site_filter,omitempty"`
}

// handleSearchEngines returns available search engines and their status.
func (s *Server) handleSearchEngines(w http.ResponseWriter, r *http.Request) {
	if s.searchOrchestrator == nil {
		writeErr(w, http.StatusServiceUnavailable, "search not initialized")
		return
	}
	if localURL := search.DetectLocalSearXNG(); localURL != "" {
		s.searchOrchestrator.UpdateEngine("searxng", localURL)
	}
	stats := s.searchOrchestrator.GetStats()
	if localURL := search.DetectLocalSearXNG(); localURL != "" {
		stats["searxng_local_url"] = localURL
		stats["searxng_local_detected"] = true
	}
	stats["searxng_provisioning"] = searxngProvisioning.Load()
	writeJSON(w, http.StatusOK, stats)
}

// handleSearch performs a multi-engine web search.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if s.searchOrchestrator == nil {
		writeErr(w, http.StatusServiceUnavailable, "search not initialized")
		return
	}

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Query == "" {
		writeErr(w, http.StatusBadRequest, "query is required")
		return
	}

	// If the caller explicitly requested local SearXNG while initial provisioning is
	// still spinning up, wait briefly so the engine becomes ready transparently.
	if strings.EqualFold(strings.TrimSpace(req.Engine), "searxng") {
		s.ensureLocalSearXNGReady(r.Context(), 30*time.Second)
	}

	// Convert mode string to SearchMode
	mode := search.ModeGeneral
	switch req.Mode {
	case "news":
		mode = search.ModeNews
	case "exploit":
		mode = search.ModeExploit
	case "technical":
		mode = search.ModeTechnical
	case "osint":
		mode = search.ModeOSINT
	}

	searchReq := search.NewRequest(req.Query, mode)
	if req.Engine != "" {
		searchReq.Engine = req.Engine
	}
	if req.MaxResults > 0 {
		searchReq.MaxResults = req.MaxResults
	}
	if req.SiteFilter != "" {
		searchReq.SiteFilter = req.SiteFilter
	}

	result, err := s.searchOrchestrator.Search(r.Context(), searchReq)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "search failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// handleSearchExploit performs an exploit-specific search.
func (s *Server) handleSearchExploit(w http.ResponseWriter, r *http.Request) {
	if s.searchOrchestrator == nil {
		writeErr(w, http.StatusServiceUnavailable, "search not initialized")
		return
	}

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Query == "" {
		writeErr(w, http.StatusBadRequest, "query is required")
		return
	}

	result, err := s.searchOrchestrator.SearchExploit(r.Context(), req.Query)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "exploit search failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ==================== Browser Automation Handlers (Pentagi-inspired) ====================

// BrowserRequest is the JSON request for browser API.
type BrowserAPIRequest struct {
	URL      string `json:"url"`
	Action   string `json:"action,omitempty"` // screenshot, content, both
	FullPage bool   `json:"full_page,omitempty"`
}

// handleBrowserScreenshot captures a screenshot of a URL.
func (s *Server) handleBrowserScreenshot(w http.ResponseWriter, r *http.Request) {
	if s.browserScraper == nil || !s.browserScraper.IsAvailable() {
		writeErr(w, http.StatusServiceUnavailable, "browser not available")
		return
	}

	var req BrowserAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.URL == "" {
		writeErr(w, http.StatusBadRequest, "url is required")
		return
	}

	browserReq := browser.BrowserRequest{
		URL:      req.URL,
		Action:   browser.ActionScreenshot,
		FullPage: req.FullPage,
	}

	result, err := s.browserScraper.Handle(r.Context(), browserReq)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "screenshot failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// handleBrowserContent extracts page content as markdown.
func (s *Server) handleBrowserContent(w http.ResponseWriter, r *http.Request) {
	if s.browserScraper == nil || !s.browserScraper.IsAvailable() {
		writeErr(w, http.StatusServiceUnavailable, "browser not available")
		return
	}

	var req BrowserAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.URL == "" {
		writeErr(w, http.StatusBadRequest, "url is required")
		return
	}

	browserReq := browser.BrowserRequest{
		URL:    req.URL,
		Action: browser.ActionContent,
	}

	result, err := s.browserScraper.Handle(r.Context(), browserReq)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "content extraction failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ==================== Search & Browser Config Handlers ====================

// SearchConfigRequest is the request to update search engine config.
type SearchConfigRequest struct {
	Engine string `json:"engine"`
	APIKey string `json:"api_key"`
}

// BrowserConfigRequest is the request to update browser config.
type BrowserConfigRequest struct {
	ScraperURL     string `json:"scraper_url"`
	UseLocalChrome bool   `json:"use_local_chrome"`
}

// handleSearchConfig saves search engine configuration and hot-reloads the engine.
func (s *Server) handleSearchConfig(w http.ResponseWriter, r *http.Request) {
	var req SearchConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	eng := strings.ToLower(strings.TrimSpace(req.Engine))
	val := strings.TrimSpace(req.APIKey)
	if s.searchOrchestrator != nil {
		s.searchOrchestrator.UpdateEngine(eng, val)
	}
	if s.m != nil && s.m.pg != nil {
		switch eng {
		case "firecrawl":
			// val may be "API_KEY|BASE_URL", a bare base URL, or an API key.
			apiKey, baseURL := val, ""
			if parts := strings.SplitN(val, "|", 2); len(parts) == 2 {
				apiKey, baseURL = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			} else if strings.HasPrefix(val, "http") {
				apiKey, baseURL = "", val
			}
			_ = s.m.pg.SetSetting("search_firecrawl_api_key", apiKey)
			_ = s.m.pg.SetSetting("search_firecrawl_base_url", baseURL)
		case "tavily":
			_ = s.m.pg.SetSetting("search_tavily_api_key", val)
			on, backend, _, _, _ := s.m.WebSearch()
			_ = s.m.SetWebSearch(on, backend, nil, &val, nil)
		case "searxng":
			_ = s.m.pg.SetSetting("search_searxng_url", val)
		case "brave":
			_ = s.m.pg.SetSetting("search_brave_api_key", val)
			on, backend, _, tavilyKey, proxy := s.m.WebSearch()
			tavilyPtr := &tavilyKey
			_ = s.m.SetWebSearch(on, backend, &val, tavilyPtr, &proxy)
		}
	}
	log.Printf("[search] Config updated for engine: %s", req.Engine)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleGetBrowserConfig returns the current browser automation configuration.
func (s *Server) handleGetBrowserConfig(w http.ResponseWriter, r *http.Request) {
	if s.browserScraper == nil {
		writeErr(w, http.StatusServiceUnavailable, "browser not initialized")
		return
	}
	cfg := s.browserScraper.GetConfig()
	writeJSON(w, http.StatusOK, map[string]any{
		"scraper_url":      cfg.ScraperURL,
		"use_local_chrome": cfg.UseLocalChrome,
		"chrome_path":      cfg.ChromePath,
		"available":        s.browserScraper.IsAvailable(),
	})
}

// handleBrowserConfig saves browser configuration and hot-updates the scraper.
func (s *Server) handleBrowserConfig(w http.ResponseWriter, r *http.Request) {
	var req BrowserConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.ScraperURL = strings.TrimSpace(req.ScraperURL)
	if s.browserScraper != nil {
		s.browserScraper.UpdateConfig(req.ScraperURL, req.UseLocalChrome)
	}
	if s.m != nil && s.m.pg != nil {
		_ = s.m.pg.SetSetting("browser_scraper_url", req.ScraperURL)
		_ = s.m.pg.SetBool("browser_use_local_chrome", req.UseLocalChrome)
	}
	log.Printf("[browser] Config updated: scraper=%s local=%v", req.ScraperURL, req.UseLocalChrome)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
