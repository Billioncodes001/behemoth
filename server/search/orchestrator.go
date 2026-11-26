package search

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// Orchestrator manages multiple search engines with automatic fallback chains.
type Orchestrator struct {
	engines        map[SearchEngineType]SearchEngine
	config         *Config
	fallbackChains map[SearchMode][]SearchEngineType
	mu             sync.RWMutex
}

// NewOrchestrator creates a new search orchestrator with configured engines.
func NewOrchestrator(cfg *Config) *Orchestrator {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	o := &Orchestrator{
		engines:        make(map[SearchEngineType]SearchEngine),
		config:         cfg,
		fallbackChains: make(map[SearchMode][]SearchEngineType),
	}
	o.registerEngines()
	o.setupFallbackChains()
	return o
}

// registerEngines creates engine instances based on config.
func (o *Orchestrator) registerEngines() {
	cfg := o.config
	if cfg.Firecrawl.Enabled && (cfg.Firecrawl.APIKey != "" || cfg.Firecrawl.BaseURL != "") {
		o.engines[EngineFirecrawl] = NewFirecrawlSearchEngine(cfg.Firecrawl.APIKey, cfg.Firecrawl.BaseURL, true)
		if cfg.Firecrawl.BaseURL != "" {
			log.Printf("[search] Firecrawl search enabled (self-hosted: %s)", cfg.Firecrawl.BaseURL)
		} else {
			log.Printf("[search] Firecrawl search enabled (hosted API)")
		}
	}
	if cfg.DuckDuckGo.Enabled {
		o.engines[EngineDuckDuckGo] = NewDuckDuckGoSearchEngine(true)
		log.Printf("[search] DuckDuckGo search enabled")
	}
	if cfg.Tavily.Enabled && cfg.Tavily.APIKey != "" {
		o.engines[EngineTavily] = NewTavilySearchEngine(cfg.Tavily.APIKey, true)
		log.Printf("[search] Tavily AI search enabled")
	}
	if cfg.SearXNG.Enabled && cfg.SearXNG.URL != "" {
		o.engines[EngineSearXNG] = NewSearXNGSearchEngine(cfg.SearXNG.URL, true)
		log.Printf("[search] SearXNG search enabled at %s", cfg.SearXNG.URL)
	}
	if cfg.Brave.Enabled && cfg.Brave.APIKey != "" {
		o.engines[EngineBrave] = NewBraveSearchEngine(cfg.Brave.APIKey, true)
		log.Printf("[search] Brave search enabled")
	}
	if cfg.Sploitus.Enabled {
		o.engines[EngineSploitus] = NewSploitusSearchEngine(true)
		log.Printf("[search] Sploitus exploit search enabled")
	}
}

// setupFallbackChains defines priority order for each search mode.
// SearXNG ranks high because it runs self-hosted on the same host (free, fast,
// no rate limits) once the local instance is detected.
func (o *Orchestrator) setupFallbackChains() {
	o.fallbackChains[ModeGeneral] = []SearchEngineType{EngineTavily, EngineSearXNG, EngineFirecrawl, EngineDuckDuckGo, EngineBrave}
	o.fallbackChains[ModeNews] = []SearchEngineType{EngineSearXNG, EngineFirecrawl, EngineBrave, EngineDuckDuckGo, EngineTavily}
	o.fallbackChains[ModeExploit] = []SearchEngineType{EngineSploitus, EngineSearXNG, EngineFirecrawl, EngineBrave, EngineDuckDuckGo, EngineTavily}
	o.fallbackChains[ModeTechnical] = []SearchEngineType{EngineTavily, EngineSearXNG, EngineFirecrawl, EngineBrave, EngineDuckDuckGo}
	o.fallbackChains[ModeOSINT] = []SearchEngineType{EngineSearXNG, EngineFirecrawl, EngineBrave, EngineDuckDuckGo, EngineTavily}
}

// ensureAutoLocalSearXNG dynamically attaches the local self-hosted SearXNG
// service whenever it comes online after server boot.
func (o *Orchestrator) ensureAutoLocalSearXNG() {
	o.mu.RLock()
	existing, ok := o.engines[EngineSearXNG]
	alreadyActive := ok && existing != nil && existing.IsAvailable()
	o.mu.RUnlock()
	if alreadyActive {
		return
	}
	localURL := DetectLocalSearXNG()
	if localURL == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if existing, ok := o.engines[EngineSearXNG]; ok && existing != nil && existing.IsAvailable() {
		return
	}
	o.config.SearXNG.URL = localURL
	o.config.SearXNG.Enabled = true
	o.engines[EngineSearXNG] = NewSearXNGSearchEngine(localURL, true)
	log.Printf("[search] Auto-enabled self-hosted SearXNG at %s", localURL)
}

// Search executes a search using the appropriate fallback chain (or a specific requested engine).
func (o *Orchestrator) Search(ctx context.Context, req Request) (*SearchResult, error) {
	startTime := time.Now()
	o.ensureAutoLocalSearXNG()
	o.mu.RLock()
	if req.MaxResults <= 0 {
		req.MaxResults = o.config.MaxResults
	}
	if req.Timeout <= 0 {
		req.Timeout = o.config.DefaultTimeout
	}

	var chain []SearchEngineType
	if targetEngine := strings.ToLower(strings.TrimSpace(req.Engine)); targetEngine != "" {
		et := SearchEngineType(targetEngine)
		engine, exists := o.engines[et]
		if !exists || !engine.IsAvailable() {
			o.mu.RUnlock()
			return nil, fmt.Errorf("engine %q is not configured or not enabled — please configure its API key / URL first", targetEngine)
		}
		chain = []SearchEngineType{et}
	} else {
		chain = o.fallbackChains[req.Mode]
		if len(chain) == 0 {
			chain = o.fallbackChains[ModeGeneral]
		}
	}

	engines := make([]SearchEngine, 0, len(chain))
	for _, engineType := range chain {
		if engine, exists := o.engines[engineType]; exists && engine.IsAvailable() {
			engines = append(engines, engine)
		}
	}
	o.mu.RUnlock()

	if len(engines) == 0 {
		return nil, fmt.Errorf("no search engines are currently enabled — please enable or configure a search engine in System Settings")
	}

	var allResults []Result
	var enginesUsed []string
	var warnings []string

	for _, engine := range engines {
		engineCtx, cancel := context.WithTimeout(ctx, req.Timeout)
		resp, err := engine.Handle(engineCtx, req)
		cancel()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", engine.Engine(), err))
			if req.Engine != "" {
				return nil, err
			}
			continue
		}
		if len(resp.Results) == 0 {
			continue
		}
		for i := range resp.Results {
			resp.Results[i].Rank = len(allResults) + i + 1
		}
		allResults = append(allResults, resp.Results...)
		enginesUsed = append(enginesUsed, string(resp.Engine))
		if len(allResults) >= req.MaxResults {
			break
		}
	}

	allResults = deduplicateResults(allResults)
	if len(allResults) > req.MaxResults {
		allResults = allResults[:req.MaxResults]
	}
	if allResults == nil {
		allResults = []Result{}
	}

	dur := time.Since(startTime)
	return &SearchResult{
		Query: req.Query, Mode: req.Mode, Results: allResults,
		EnginesUsed: enginesUsed, Warnings: warnings, TotalResults: len(allResults),
		Duration: dur, QueryTimeMS: dur.Milliseconds(), Timestamp: time.Now(),
	}, nil
}

// UpdateEngine dynamically updates a search engine's configuration and re-registers engines.
func (o *Orchestrator) UpdateEngine(engine string, value string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	val := strings.TrimSpace(value)
	switch SearchEngineType(strings.ToLower(strings.TrimSpace(engine))) {
	case EngineFirecrawl:
		// Accept "API_KEY|BASE_URL", "API_KEY:BASE_URL", a bare base URL, or just an API key.
		apiKey, baseURL := "", ""
		if parts := strings.SplitN(val, "|", 2); len(parts) == 2 {
			apiKey, baseURL = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		} else if parts := strings.SplitN(val, ":", 2); len(parts) == 2 && strings.HasPrefix(val, "http") {
			apiKey, baseURL = "", val
		} else if strings.HasPrefix(val, "http") {
			baseURL = val
		} else {
			apiKey = val
		}
		o.config.Firecrawl.APIKey = apiKey
		o.config.Firecrawl.BaseURL = baseURL
		o.config.Firecrawl.Enabled = apiKey != "" || baseURL != ""
		if !o.config.Firecrawl.Enabled {
			delete(o.engines, EngineFirecrawl)
		}
	case EngineTavily:
		o.config.Tavily.APIKey = val
		o.config.Tavily.Enabled = val != ""
		if !o.config.Tavily.Enabled {
			delete(o.engines, EngineTavily)
		}
	case EngineBrave:
		o.config.Brave.APIKey = val
		o.config.Brave.Enabled = val != ""
		if !o.config.Brave.Enabled {
			delete(o.engines, EngineBrave)
		}
	case EngineSearXNG:
		o.config.SearXNG.URL = val
		o.config.SearXNG.Enabled = val != ""
		if !o.config.SearXNG.Enabled {
			delete(o.engines, EngineSearXNG)
		}
	case EngineDuckDuckGo:
		o.config.DuckDuckGo.Enabled = val != "false" && val != "0"
		if !o.config.DuckDuckGo.Enabled {
			delete(o.engines, EngineDuckDuckGo)
		}
	case EngineSploitus:
		o.config.Sploitus.Enabled = val != "false" && val != "0"
		if !o.config.Sploitus.Enabled {
			delete(o.engines, EngineSploitus)
		}
	}
	o.registerEngines()
}

// SearchExploit is a convenience method for exploit-specific searches.
func (o *Orchestrator) SearchExploit(ctx context.Context, query string) (*SearchResult, error) {
	return o.Search(ctx, Request{Query: query, Mode: ModeExploit, MaxResults: 15})
}

// SearchTechnical is a convenience method for technical searches.
func (o *Orchestrator) SearchTechnical(ctx context.Context, query string) (*SearchResult, error) {
	return o.Search(ctx, Request{Query: query, Mode: ModeTechnical, MaxResults: 10})
}

// GetAvailableEngines returns list of currently available engines.
func (o *Orchestrator) GetAvailableEngines() []SearchEngineType {
	o.ensureAutoLocalSearXNG()
	o.mu.RLock()
	defer o.mu.RUnlock()
	var available []SearchEngineType
	for t, e := range o.engines {
		if e.IsAvailable() {
			available = append(available, t)
		}
	}
	return available
}

// GetStats returns statistics about the orchestrator.
func (o *Orchestrator) GetStats() map[string]interface{} {
	o.ensureAutoLocalSearXNG()
	o.mu.RLock()
	defer o.mu.RUnlock()
	allTypes := []SearchEngineType{EngineFirecrawl, EngineDuckDuckGo, EngineTavily, EngineSearXNG, EngineBrave, EngineSploitus}
	engineStatus := make(map[string]bool, len(allTypes))
	availableCount := 0
	for _, t := range allTypes {
		if e, ok := o.engines[t]; ok && e.IsAvailable() {
			engineStatus[string(t)] = true
			availableCount++
		} else {
			engineStatus[string(t)] = false
		}
	}
	configuredKeys := map[string]bool{
		"firecrawl": o.config.Firecrawl.APIKey != "" || o.config.Firecrawl.BaseURL != "",
		"tavily":    o.config.Tavily.APIKey != "",
		"brave":     o.config.Brave.APIKey != "",
		"searxng":   o.config.SearXNG.URL != "",
	}
	return map[string]interface{}{
		"total_engines_registered": len(allTypes),
		"available_engines":        availableCount,
		"engine_status":            engineStatus,
		"configured_keys":          configuredKeys,
		"searxng_url":              o.config.SearXNG.URL,
		"firecrawl_url":            o.config.Firecrawl.BaseURL,
	}
}

// deduplicateResults removes duplicate URLs, keeping first occurrence.
func deduplicateResults(results []Result) []Result {
	seen := make(map[string]bool)
	var unique []Result
	for _, r := range results {
		if !seen[r.URL] && r.URL != "" {
			seen[r.URL] = true
			unique = append(unique, r)
		}
	}
	return unique
}
