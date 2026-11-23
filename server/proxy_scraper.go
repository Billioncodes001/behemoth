package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/db"
	proxyv2 "github.com/Autumn-27/artex/server/proxy/v2"
	actool "github.com/Autumn-27/norma/tool"
	"golang.org/x/net/proxy"
)

const (
	scrapedProxyPrefix           = "scraped-"
	settingProxyScraperConfig    = "proxy_scraper_config_v1"
	settingProxyScraperSources   = "proxy_scraper_sources_v1"
	maxScraperLogEntries         = 300
	defaultScrapeIntervalMinutes = 30
	defaultScrapeMaxProxies      = 25
	defaultScrapeMaxLatencyMS    = 4500
	defaultMaxCandidatesToCheck  = 350
)

type ProxyScraperConfig struct {
	Enabled         bool     `json:"enabled"`
	AIAgentEnabled  bool     `json:"ai_agent_enabled"`
	AutoEnablePool  bool     `json:"auto_enable_pool"`
	IntervalMinutes int      `json:"interval_minutes"`
	MaxProxies      int      `json:"max_proxies"`
	MaxLatencyMS    int      `json:"max_latency_ms"`
	Protocols       []string `json:"protocols"` // ["socks5", "http"]
}

type ProxyScrapeSource struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	Protocol       string `json:"protocol"` // "socks5" | "http"
	Priority       bool   `json:"priority"` // true = pre-checked/fast feed checked first
	Builtin        bool   `json:"builtin"`
	AddedByAgent   bool   `json:"added_by_agent,omitempty"`
	Enabled        bool   `json:"enabled"`
	LastCandidates int    `json:"last_candidates"`
	LastVerified   int    `json:"last_verified"`
	LastError      string `json:"last_error,omitempty"`
	LastPolledAt   string `json:"last_polled_at,omitempty"`
}

type ProxyScraperLogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"` // info | source | verified | warn | ai | summary
	Message   string `json:"message"`
}

type proxyScraperRuntime struct {
	mu              sync.RWMutex
	running         bool
	aiRunning       bool
	phase           string
	sourcesPolled   int
	candidatesFound int
	tcpAlive        int
	httpsVerified   int
	addedToPool     int
	lastRunAt       string
	nextRunAt       string
	lastAgentConvID int64
	logs            []ProxyScraperLogEntry
	cancelRun       context.CancelFunc
	wakeCh          chan struct{}
	sourceStats     map[string]ProxyScrapeSource
}

var scraperRT = &proxyScraperRuntime{
	wakeCh:      make(chan struct{}, 1),
	sourceStats: map[string]ProxyScrapeSource{},
}

var builtinProxyScrapeSources = []ProxyScrapeSource{
	{
		ID: "monosans-socks5", Name: "monosans/proxy-list (SOCKS5 · Hourly Speed-Sorted)",
		URL: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "monosans-http", Name: "monosans/proxy-list (HTTP · Hourly Speed-Sorted)",
		URL: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxifly-socks5", Name: "proxifly/free-proxy-list (SOCKS5 · 5m Live)",
		URL: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxifly-http", Name: "proxifly/free-proxy-list (HTTP · 5m Live)",
		URL: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxyscrape-socks5", Name: "ProxyScrape API v2 (SOCKS5 · Fast)",
		URL: "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=4500&country=all",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxyscrape-https-elite", Name: "ProxyScrape API v2 (HTTPS · Elite/Anonymous)",
		URL: "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=4500&ssl=yes&anonymity=elite,anonymous",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "jetkai-socks5", Name: "jetkai/proxy-list (Online SOCKS5)",
		URL: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "jetkai-https", Name: "jetkai/proxy-list (Online HTTPS)",
		URL: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "dinoz0rg-socks5", Name: "dinoz0rg/proxy-list (Checked SOCKS5)",
		URL: "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/socks5.txt",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "elliottophellia-socks5", Name: "elliottophellia/proxylist (Checked SOCKS5)",
		URL: "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/socks5/global/socks5_checked.txt",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "hookzof-socks5", Name: "hookzof/socks5_list (SOCKS5)",
		URL: "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
		Protocol: "socks5", Priority: false, Builtin: true, Enabled: true,
	},
	{
		ID: "hideip-socks5", Name: "zloi-user/hideip.me (SOCKS5 · 10m)",
		URL: "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
		Protocol: "socks5", Priority: false, Builtin: true, Enabled: true,
	},
	{
		ID: "hideip-connect", Name: "zloi-user/hideip.me (HTTPS CONNECT · 10m)",
		URL: "https://raw.githubusercontent.com/zloi-user/hideip.me/main/connect.txt",
		Protocol: "http", Priority: false, Builtin: true, Enabled: true,
	},
	{
		ID: "sunny9577-socks5", Name: "sunny9577/proxy-scraper (SOCKS5 · 3h)",
		URL: "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
		Protocol: "socks5", Priority: false, Builtin: true, Enabled: true,
	},
	{
		ID: "thespeedx-socks5", Name: "TheSpeedX/PROXY-List (SOCKS5)",
		URL: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
		Protocol: "socks5", Priority: false, Builtin: true, Enabled: true,
	},
	{
		ID: "thespeedx-http", Name: "TheSpeedX/PROXY-List (HTTP)",
		URL: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		Protocol: "http", Priority: false, Builtin: true, Enabled: true,
	},
}

var (
	reScrapedSchemeHostPort = regexp.MustCompile(`(?i)\b(socks5h?|https?)://((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b`)
	reScrapedBareHostPort   = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b`)
)

func defaultProxyScraperConfig() ProxyScraperConfig {
	return ProxyScraperConfig{
		Enabled:         false,
		AIAgentEnabled:  true,
		AutoEnablePool:  true,
		IntervalMinutes: defaultScrapeIntervalMinutes,
		MaxProxies:      defaultScrapeMaxProxies,
		MaxLatencyMS:    defaultScrapeMaxLatencyMS,
		Protocols:       []string{"socks5", "http"},
	}
}

func normalizeScraperConfig(cfg ProxyScraperConfig) ProxyScraperConfig {
	if cfg.IntervalMinutes < 5 {
		cfg.IntervalMinutes = defaultScrapeIntervalMinutes
	}
	if cfg.IntervalMinutes > 1440 {
		cfg.IntervalMinutes = 1440
	}
	if cfg.MaxProxies < 3 {
		cfg.MaxProxies = defaultScrapeMaxProxies
	}
	if cfg.MaxProxies > 100 {
		cfg.MaxProxies = 100
	}
	if cfg.MaxLatencyMS < 500 {
		cfg.MaxLatencyMS = defaultScrapeMaxLatencyMS
	}
	if cfg.MaxLatencyMS > 15000 {
		cfg.MaxLatencyMS = 15000
	}
	var cleanProtos []string
	seen := map[string]bool{}
	for _, p := range cfg.Protocols {
		pl := strings.ToLower(strings.TrimSpace(p))
		if (pl == "socks5" || pl == "http") && !seen[pl] {
			seen[pl] = true
			cleanProtos = append(cleanProtos, pl)
		}
	}
	if len(cleanProtos) == 0 {
		cleanProtos = []string{"socks5", "http"}
	}
	cfg.Protocols = cleanProtos
	return cfg
}

func (s *Server) loadProxyScraperConfig() ProxyScraperConfig {
	cfg := defaultProxyScraperConfig()
	if s != nil && s.m != nil && s.m.pg != nil {
		if raw, ok, _ := s.m.pg.GetSetting(settingProxyScraperConfig); ok && strings.TrimSpace(raw) != "" {
			_ = json.Unmarshal([]byte(raw), &cfg)
		}
	}
	return normalizeScraperConfig(cfg)
}

func (s *Server) saveProxyScraperConfig(cfg ProxyScraperConfig) error {
	cfg = normalizeScraperConfig(cfg)
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.m.pg.SetSetting(settingProxyScraperConfig, string(b))
}

func (s *Server) loadAllProxyScrapeSources() []ProxyScrapeSource {
	var custom []ProxyScrapeSource
	if s != nil && s.m != nil && s.m.pg != nil {
		if raw, ok, _ := s.m.pg.GetSetting(settingProxyScraperSources); ok && strings.TrimSpace(raw) != "" {
			_ = json.Unmarshal([]byte(raw), &custom)
		}
	}
	out := make([]ProxyScrapeSource, 0, len(builtinProxyScrapeSources)+len(custom))
	scraperRT.mu.RLock()
	for _, src := range append(append([]ProxyScrapeSource{}, builtinProxyScrapeSources...), custom...) {
		if st, ok := scraperRT.sourceStats[src.ID]; ok {
			src.LastCandidates = st.LastCandidates
			src.LastVerified = st.LastVerified
			src.LastError = st.LastError
			src.LastPolledAt = st.LastPolledAt
		}
		out = append(out, src)
	}
	scraperRT.mu.RUnlock()
	return out
}

func (s *Server) saveCustomProxyScrapeSources(custom []ProxyScrapeSource) error {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil
	}
	b, err := json.Marshal(custom)
	if err != nil {
		return err
	}
	return s.m.pg.SetSetting(settingProxyScraperSources, string(b))
}

func appendScraperLog(level, msg string) {
	entry := ProxyScraperLogEntry{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     level,
		Message:   msg,
	}
	scraperRT.mu.Lock()
	scraperRT.logs = append(scraperRT.logs, entry)
	if len(scraperRT.logs) > maxScraperLogEntries {
		scraperRT.logs = scraperRT.logs[len(scraperRT.logs)-maxScraperLogEntries:]
	}
	scraperRT.mu.Unlock()
}

type rawCandidateProxy struct {
	Protocol string
	Host     string
	Port     int
	SourceID string
	Priority bool
}

type verifiedCandidateProxy struct {
	rawCandidateProxy
	ExitIP    string
	LatencyMS int64
	Country   string
	City      string
}

func extractProxiesFromBody(body, defaultProto, sourceID string, priority bool) []rawCandidateProxy {
	var out []rawCandidateProxy
	seen := map[string]bool{}

	add := func(proto, host, portStr string) {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return
		}
		pl := strings.ToLower(proto)
		if strings.HasPrefix(pl, "socks5") {
			pl = "socks5"
		} else {
			pl = "http"
		}
		key := pl + "://" + host + ":" + strconv.Itoa(p)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, rawCandidateProxy{
			Protocol: pl, Host: host, Port: p, SourceID: sourceID, Priority: priority,
		})
	}

	for _, m := range reScrapedSchemeHostPort.FindAllStringSubmatch(body, 5000) {
		add(m[1], m[2], m[3])
	}
	remaining := reScrapedSchemeHostPort.ReplaceAllString(body, " ")
	for _, m := range reScrapedBareHostPort.FindAllStringSubmatch(remaining, 5000) {
		add(defaultProto, m[1], m[2])
	}
	return out
}

func resolveSelfPublicIP(ctx context.Context) string {
	cl := &http.Client{
		Timeout:   4 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	for _, u := range []string{"https://ipv4.icanhazip.com", "https://checkip.amazonaws.com"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := cl.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// verifyCandidateTwoStage implements monosans/proxy-scraper-checker's 2-stage check:
// Stage 1: Fast raw TCP connect (2.5s) to drop dead hosts immediately.
// Stage 2: Full HTTPS fetch with strict TLS certificate verification (InsecureSkipVerify=false)
// and Elite/Anonymous exit-IP validation (rejecting transparent proxies where exitIP == selfIP).
func verifyCandidateTwoStage(ctx context.Context, cand rawCandidateProxy, selfIP string, maxLatency time.Duration) (verifiedCandidateProxy, bool) {
	addr := net.JoinHostPort(cand.Host, strconv.Itoa(cand.Port))

	// Stage 1: Fast TCP pre-filter
	tcpConn, err := (&net.Dialer{Timeout: 2500 * time.Millisecond}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return verifiedCandidateProxy{}, false
	}
	_ = tcpConn.Close()

	scraperRT.mu.Lock()
	scraperRT.tcpAlive++
	scraperRT.mu.Unlock()

	// Stage 2: Strict TLS HTTPS + Non-Transparent Exit-IP check
	proxyURLStr := fmt.Sprintf("%s://%s", cand.Protocol, addr)
	parsed, err := url.Parse(proxyURLStr)
	if err != nil {
		return verifiedCandidateProxy{}, false
	}

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: false},
		DisableKeepAlives: true,
	}
	if cand.Protocol == "socks5" {
		dialer, derr := proxy.FromURL(parsed, &net.Dialer{Timeout: 3500 * time.Millisecond})
		if derr != nil {
			return verifiedCandidateProxy{}, false
		}
		tr.DialContext = func(_ context.Context, network, targetAddr string) (net.Conn, error) {
			return dialer.Dial(network, targetAddr)
		}
	} else {
		tr.Proxy = http.ProxyURL(parsed)
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr, Timeout: maxLatency}
	checkEndpoints := []string{
		"https://ipv4.icanhazip.com",
		"https://api.ipify.org?format=json",
	}

	for _, testURL := range checkEndpoints {
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if rerr != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")
		t0 := time.Now()
		resp, derr := client.Do(req)
		lat := time.Since(t0)
		if derr != nil {
			continue
		}
		body, berr := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		if berr != nil || resp.StatusCode != http.StatusOK || lat > maxLatency {
			continue
		}

		var exitIP string
		var jsonIP struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(body, &jsonIP) == nil && jsonIP.IP != "" {
			exitIP = strings.TrimSpace(jsonIP.IP)
		} else {
			exitIP = strings.TrimSpace(string(body))
		}
		if net.ParseIP(exitIP) == nil {
			continue
		}
		// Reject transparent proxies that expose our server's real outbound IP!
		if selfIP != "" && exitIP == selfIP {
			appendScraperLog("warn", fmt.Sprintf("[REJECTED] %s://%s — transparent proxy leaked host IP", cand.Protocol, addr))
			return verifiedCandidateProxy{}, false
		}

		return verifiedCandidateProxy{
			rawCandidateProxy: cand,
			ExitIP:            exitIP,
			LatencyMS:         lat.Milliseconds(),
		}, true
	}
	return verifiedCandidateProxy{}, false
}

func lookupQuickGeo(ip string) (string, string) {
	cl := &http.Client{Timeout: 2500 * time.Millisecond, Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Get("http://ip-api.com/json/" + url.PathEscape(ip) + "?fields=status,country,city")
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	var g struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		City    string `json:"city"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&g) == nil && g.Status == "success" {
		return g.Country, g.City
	}
	return "", ""
}

func (s *Server) startProxyScraperSupervisor(ctx context.Context) {
	go func() {
		// Short startup check if auto-scrape is persisted enabled
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
			if cfg := s.loadProxyScraperConfig(); cfg.Enabled {
				s.runOnlineScrapeCycle(ctx, false)
			}
		}

		for {
			cfg := s.loadProxyScraperConfig()
			waitDur := time.Duration(cfg.IntervalMinutes) * time.Minute
			if waitDur < 5*time.Minute {
				waitDur = 30 * time.Minute
			}
			if cfg.Enabled {
				scraperRT.mu.Lock()
				scraperRT.nextRunAt = time.Now().UTC().Add(waitDur).Format(time.RFC3339)
				scraperRT.mu.Unlock()
			} else {
				scraperRT.mu.Lock()
				scraperRT.nextRunAt = ""
				scraperRT.mu.Unlock()
			}

			timer := time.NewTimer(waitDur)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-scraperRT.wakeCh:
				timer.Stop()
				if c := s.loadProxyScraperConfig(); c.Enabled {
					s.runOnlineScrapeCycle(ctx, false)
				}
			case <-timer.C:
				if c := s.loadProxyScraperConfig(); c.Enabled {
					s.runOnlineScrapeCycle(ctx, false)
				}
			}
		}
	}()
}

func (s *Server) runOnlineScrapeCycle(parentCtx context.Context, manual bool) map[string]any {
	scraperRT.mu.Lock()
	if scraperRT.running {
		scraperRT.mu.Unlock()
		return s.scraperStatusSnapshot()
	}
	runCtx, cancel := context.WithTimeout(parentCtx, 3*time.Minute)
	scraperRT.running = true
	scraperRT.phase = "Fetching online proxy feeds..."
	scraperRT.sourcesPolled = 0
	scraperRT.candidatesFound = 0
	scraperRT.tcpAlive = 0
	scraperRT.httpsVerified = 0
	scraperRT.addedToPool = 0
	scraperRT.cancelRun = cancel
	scraperRT.mu.Unlock()

	defer func() {
		cancel()
		scraperRT.mu.Lock()
		scraperRT.running = false
		scraperRT.phase = "Idle"
		scraperRT.lastRunAt = time.Now().UTC().Format(time.RFC3339)
		scraperRT.cancelRun = nil
		scraperRT.mu.Unlock()
	}()

	cfg := s.loadProxyScraperConfig()
	allowedProto := map[string]bool{}
	for _, p := range cfg.Protocols {
		allowedProto[p] = true
	}

	sources := s.loadAllProxyScrapeSources()
	var activeSources []ProxyScrapeSource
	for _, src := range sources {
		if src.Enabled && allowedProto[src.Protocol] {
			activeSources = append(activeSources, src)
		}
	}

	appendScraperLog("info", fmt.Sprintf("Starting online proxy scrape across %d sources (protocols: %s, max keep: %d, max latency: %dms)...",
		len(activeSources), strings.Join(cfg.Protocols, ", "), cfg.MaxProxies, cfg.MaxLatencyMS))

	selfIP := resolveSelfPublicIP(runCtx)
	if selfIP != "" {
		appendScraperLog("info", "Host IP leak-guard baseline initialized (transparent proxies echoing host IP will be rejected).")
	}

	// Fetch all sources concurrently using SSRF-guarded direct HTTP client
	fetchClient := newSafePublicFeedClient(8 * time.Second)
	var candMu sync.Mutex
	var priorityCands, bulkCands []rawCandidateProxy
	var fwg sync.WaitGroup

	for _, src := range activeSources {
		src := src
		fwg.Add(1)
		go func() {
			defer fwg.Done()
			t0 := time.Now()
			req, err := http.NewRequestWithContext(runCtx, http.MethodGet, src.URL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36")
			resp, err := fetchClient.Do(req)
			nowStr := time.Now().UTC().Format(time.RFC3339)
			if err != nil {
				scraperRT.mu.Lock()
				st := scraperRT.sourceStats[src.ID]
				st.ID = src.ID
				st.LastError = firstLine(err.Error(), 120)
				st.LastPolledAt = nowStr
				scraperRT.sourceStats[src.ID] = st
				scraperRT.mu.Unlock()
				appendScraperLog("warn", fmt.Sprintf("[SOURCE] %s failed: %s", src.Name, firstLine(err.Error(), 90)))
				return
			}
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				scraperRT.mu.Lock()
				st := scraperRT.sourceStats[src.ID]
				st.ID = src.ID
				st.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
				st.LastPolledAt = nowStr
				scraperRT.sourceStats[src.ID] = st
				scraperRT.mu.Unlock()
				appendScraperLog("warn", fmt.Sprintf("[SOURCE] %s returned HTTP %d", src.Name, resp.StatusCode))
				return
			}

			extracted := extractProxiesFromBody(string(bodyBytes), src.Protocol, src.ID, src.Priority)
			scraperRT.mu.Lock()
			scraperRT.sourcesPolled++
			st := scraperRT.sourceStats[src.ID]
			st.ID = src.ID
			st.LastCandidates = len(extracted)
			st.LastError = ""
			st.LastPolledAt = nowStr
			scraperRT.sourceStats[src.ID] = st
			scraperRT.mu.Unlock()

			appendScraperLog("source", fmt.Sprintf("[SOURCE] %s -> %d proxy candidates (%dms)", src.Name, len(extracted), time.Since(t0).Milliseconds()))

			candMu.Lock()
			if src.Priority {
				priorityCands = append(priorityCands, extracted...)
			} else {
				bulkCands = append(bulkCands, extracted...)
			}
			candMu.Unlock()
		}()
	}
	fwg.Wait()

	// Deduplicate across all sources, keeping SOCKS5 & priority pre-checked sources first!
	seenKey := map[string]bool{}
	var deduped []rawCandidateProxy
	sort.SliceStable(priorityCands, func(i, j int) bool {
		return priorityCands[i].Protocol == "socks5" && priorityCands[j].Protocol != "socks5"
	})
	for _, c := range append(priorityCands, bulkCands...) {
		k := c.Protocol + "://" + c.Host + ":" + strconv.Itoa(c.Port)
		if !seenKey[k] {
			seenKey[k] = true
			deduped = append(deduped, c)
		}
	}

	totalDeduped := len(deduped)
	if len(deduped) > defaultMaxCandidatesToCheck {
		deduped = deduped[:defaultMaxCandidatesToCheck]
	}

	scraperRT.mu.Lock()
	scraperRT.candidatesFound = totalDeduped
	scraperRT.phase = fmt.Sprintf("2-Stage TLS + Elite verification (%d candidates)...", len(deduped))
	scraperRT.mu.Unlock()

	appendScraperLog("info", fmt.Sprintf("Deduplicated %d unique proxies -> running 2-stage TCP + strict HTTPS/Elite verification on top %d candidates...",
		totalDeduped, len(deduped)))

	verified := s.verifyAndImportCandidates(runCtx, deduped, selfIP, cfg)

	// Trigger self-improving AI Proxy Harvester agent when enabled and either manual or pool needs more yield!
	if cfg.AIAgentEnabled && (len(verified) < cfg.MaxProxies/2 || manual) {
		go s.launchProxyHarvesterAgentRun(len(verified), cfg.MaxProxies)
	}

	return s.scraperStatusSnapshot()
}

func (s *Server) verifyAndImportCandidates(ctx context.Context, candidates []rawCandidateProxy, selfIP string, cfg ProxyScraperConfig) []verifiedCandidateProxy {
	maxLat := time.Duration(cfg.MaxLatencyMS) * time.Millisecond
	targetGoal := cfg.MaxProxies * 2 // Stop early once we have 2x needed verified proxies and sort fastest
	var verifiedCount atomic.Int64

	var resMu sync.Mutex
	var verified []verifiedCandidateProxy
	bySourceVerified := map[string]int{}

	sem := make(chan struct{}, 50)
	var vwg sync.WaitGroup
	checkCtx, cancelChecks := context.WithCancel(ctx)
	defer cancelChecks()

	for _, cand := range candidates {
		if checkCtx.Err() != nil {
			break
		}
		cand := cand
		vwg.Add(1)
		go func() {
			defer vwg.Done()
			select {
			case sem <- struct{}{}:
			case <-checkCtx.Done():
				return
			}
			defer func() { <-sem }()

			vp, ok := verifyCandidateTwoStage(checkCtx, cand, selfIP, maxLat)
			if !ok {
				return
			}
			resMu.Lock()
			verified = append(verified, vp)
			bySourceVerified[vp.SourceID]++
			resMu.Unlock()

			scraperRT.mu.Lock()
			scraperRT.httpsVerified++
			scraperRT.mu.Unlock()

			if int(verifiedCount.Add(1)) >= targetGoal {
				cancelChecks()
			}
		}()
	}
	vwg.Wait()

	scraperRT.mu.Lock()
	for srcID, cnt := range bySourceVerified {
		st := scraperRT.sourceStats[srcID]
		st.ID = srcID
		st.LastVerified = cnt
		scraperRT.sourceStats[srcID] = st
	}
	scraperRT.mu.Unlock()

	// Sort fastest-first!
	sort.Slice(verified, func(i, j int) bool {
		return verified[i].LatencyMS < verified[j].LatencyMS
	})
	if len(verified) > cfg.MaxProxies {
		verified = verified[:cfg.MaxProxies]
	}

	// Enrich top verified proxies with GeoIP & import into Proxy Pool v2
	if ppV2 != nil && ppV2.Pool != nil && len(verified) > 0 {
		now := time.Now()
		poolEntries := make([]proxyv2.ProxyInfo, 0, len(verified))
		for i := range verified {
			country, city := lookupQuickGeo(verified[i].ExitIP)
			verified[i].Country = country
			verified[i].City = city

			loc := country
			if city != "" && country != "" {
				loc = country + " · " + city
			} else if loc == "" {
				loc = "Global"
			}
			appendScraperLog("verified", fmt.Sprintf("[VERIFIED] %s://%s:%d -> Exit %s (%s, %dms, TLS+Elite)",
				verified[i].Protocol, verified[i].Host, verified[i].Port, verified[i].ExitIP, loc, verified[i].LatencyMS))

			pt := proxyv2.ProxyTypeHTTP
			if verified[i].Protocol == "socks5" {
				pt = proxyv2.ProxyTypeSOCKS5
			}
			poolEntries = append(poolEntries, proxyv2.ProxyInfo{
				ID:          fmt.Sprintf("%s%s-%s-%d", scrapedProxyPrefix, verified[i].Protocol, strings.ReplaceAll(verified[i].Host, ".", "-"), verified[i].Port),
				Type:        pt,
				Host:        verified[i].Host,
				Port:        verified[i].Port,
				Country:     country,
				City:        city,
				Status:      proxyv2.StatusHealthy,
				Active:      true,
				LastChecked: now,
				SuccessRate: 1.0,
				Latency:     time.Duration(verified[i].LatencyMS) * time.Millisecond,
				LatencyMS:   verified[i].LatencyMS,
				ResponseIP:  verified[i].ExitIP,
				Name:        fmt.Sprintf("Scraped %s (%s)", strings.ToUpper(verified[i].Protocol), loc),
				Notes:       fmt.Sprintf("Auto-scraped & 2-stage HTTPS/Elite verified (%s)", verified[i].SourceID),
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}

		// Merge with any already-healthy scraped-* proxies in the pool, deduplicate by
		// Host:Port, sort fastest-first, and cap at cfg.MaxProxies so incremental AI
		// harvester runs upgrade/top-up the pool without wiping healthy scraped proxies!
		byHostPort := map[string]proxyv2.ProxyInfo{}
		rawExisting, _, _ := ppV2.Pool.GetRawState()
		for _, ex := range rawExisting {
			if strings.HasPrefix(ex.ID, scrapedProxyPrefix) && ex.Active && (ex.Status == proxyv2.StatusHealthy || ex.Status == proxyv2.StatusInUse) {
				byHostPort[fmt.Sprintf("%s:%d", ex.Host, ex.Port)] = ex
			}
		}
		for _, np := range poolEntries {
			byHostPort[fmt.Sprintf("%s:%d", np.Host, np.Port)] = np
		}
		merged := make([]proxyv2.ProxyInfo, 0, len(byHostPort))
		for _, item := range byHostPort {
			merged = append(merged, item)
		}
		sort.Slice(merged, func(i, j int) bool {
			return merged[i].LatencyMS < merged[j].LatencyMS
		})
		if len(merged) > cfg.MaxProxies {
			merged = merged[:cfg.MaxProxies]
		}

		_ = ppV2.Pool.ReplaceManagedPrefixProxies(scrapedProxyPrefix, merged, cfg.AutoEnablePool)
		s.syncProxyPoolNow()

		scraperRT.mu.Lock()
		scraperRT.addedToPool = len(merged)
		scraperRT.mu.Unlock()
		appendScraperLog("summary", fmt.Sprintf("Scrape complete: %d fast Elite/HTTPS-verified proxies active in Proxy Pool (fastest: %dms).",
			len(merged), merged[0].LatencyMS))
	} else {
		appendScraperLog("warn", "Scrape finished with 0 candidates passing strict HTTPS + Elite non-transparent verification.")
	}

	return verified
}

// launchProxyHarvesterAgentRun runs the autonomous self-improving "proxy_harvester"
// agent to audit feed yields, discover fresh online proxy repos/APIs, register new
// sources, and verify/import extra Elite proxies.
func (s *Server) launchProxyHarvesterAgentRun(lastVerified, targetMax int) int64 {
	if s == nil || s.m == nil || s.m.pg == nil {
		return 0
	}
	scraperRT.mu.Lock()
	if scraperRT.aiRunning {
		id := scraperRT.lastAgentConvID
		scraperRT.mu.Unlock()
		return id
	}
	scraperRT.aiRunning = true
	scraperRT.mu.Unlock()

	title := fmt.Sprintf("Proxy Harvester · %s", time.Now().Format("15:04:05"))
	conv, err := s.m.pg.CreateConversation("proxy_harvester", title, nil)
	if err != nil || conv == nil {
		scraperRT.mu.Lock()
		scraperRT.aiRunning = false
		scraperRT.mu.Unlock()
		log.Printf("[proxy-harvester] create conversation failed: %v", err)
		return 0
	}

	scraperRT.mu.Lock()
	scraperRT.lastAgentConvID = conv.ID
	scraperRT.mu.Unlock()

	appendScraperLog("ai", fmt.Sprintf("[AI-HARVESTER] Launched autonomous Proxy Harvester agent (Conversation #%d) to discover & self-improve proxy sources...", conv.ID))

	prompt := fmt.Sprintf(
		"Online Proxy Scraper cycle just finished with %d verified Elite proxies (target pool size: %d).\n\n"+
			"Execute your self-improving Proxy Harvester workflow now:\n"+
			"1. Call `list_proxy_scrape_sources` to inspect which feeds produced verified proxies and which failed or returned 0 candidates (remove broken custom feeds with `remove_proxy_scrape_source`).\n"+
			"2. Search GitHub API and the web (`Bash` curl to `https://api.github.com/search/repositories?q=socks5+proxy+list&sort=updated&order=desc`, `multi_engine_search`, `WebFetch`) to discover actively updated free SOCKS5 or HTTPS proxy feeds not yet in `list_proxy_scrape_sources`.\n"+
			"3. Register 1–3 high-yield newly discovered raw feed URLs via `add_proxy_scrape_source` (with `test_immediately: true`), and if you extract proxies from a JSON/HTML API via `Bash`/Python, pass them through `verify_and_import_scraped_proxies`.\n"+
			"4. Conclude with a concise summary of newly added feeds and verified Elite proxies.",
		lastVerified, targetMax,
	)

	_, _ = s.m.pg.AppendConvActivity(conv.ID, db.Activity{
		Worker: "proxy_harvester", Kind: "user", Summary: title, Detail: prompt,
	})
	busyKey := s.convBusyKey(conv.ID)
	s.chatMu.Lock()
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()

	go func() {
		defer func() {
			scraperRT.mu.Lock()
			scraperRT.aiRunning = false
			scraperRT.mu.Unlock()
			appendScraperLog("ai", fmt.Sprintf("[AI-HARVESTER] Proxy Harvester agent finished self-improvement run (Conversation #%d).", conv.ID))
		}()
		s.runConversationSync(conv, prompt, busyKey)
	}()

	return conv.ID
}

func (s *Server) scraperStatusSnapshot() map[string]any {
	cfg := s.loadProxyScraperConfig()
	sources := s.loadAllProxyScrapeSources()
	scraperRT.mu.RLock()
	logsCopy := make([]ProxyScraperLogEntry, len(scraperRT.logs))
	copy(logsCopy, scraperRT.logs)
	out := map[string]any{
		"config":             cfg,
		"running":            scraperRT.running,
		"ai_running":         scraperRT.aiRunning,
		"phase":              scraperRT.phase,
		"sources_polled":     scraperRT.sourcesPolled,
		"candidates_found":   scraperRT.candidatesFound,
		"tcp_alive":          scraperRT.tcpAlive,
		"https_verified":     scraperRT.httpsVerified,
		"added_to_pool":      scraperRT.addedToPool,
		"last_run_at":        scraperRT.lastRunAt,
		"next_run_at":        scraperRT.nextRunAt,
		"last_agent_conv_id": scraperRT.lastAgentConvID,
		"sources":            sources,
		"logs":               logsCopy,
	}
	scraperRT.mu.RUnlock()
	return out
}

// ============================================================================
// HTTP Handlers under /api/v2/proxy-pool/scraper/*
// ============================================================================

func (s *Server) handleScraperStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.scraperStatusSnapshot())
}

func (s *Server) handleScraperSaveConfig(w http.ResponseWriter, r *http.Request) {
	var cfg ProxyScraperConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	prev := s.loadProxyScraperConfig()
	if err := s.saveProxyScraperConfig(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	normalized := s.loadProxyScraperConfig()
	if normalized.Enabled && !prev.Enabled {
		appendScraperLog("info", "Automatic online proxy scraper enabled — triggering initial scrape cycle...")
		go s.runOnlineScrapeCycle(s.ctx, true)
	}
	writeJSON(w, http.StatusOK, s.scraperStatusSnapshot())
}

func (s *Server) handleScraperRunNow(w http.ResponseWriter, r *http.Request) {
	go s.runOnlineScrapeCycle(s.ctx, true)
	time.Sleep(80 * time.Millisecond)
	writeJSON(w, http.StatusAccepted, s.scraperStatusSnapshot())
}

func (s *Server) handleScraperRunAgent(w http.ResponseWriter, r *http.Request) {
	cfg := s.loadProxyScraperConfig()
	convID := s.launchProxyHarvesterAgentRun(0, cfg.MaxProxies)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":              convID > 0,
		"conversation_id": convID,
		"status":          s.scraperStatusSnapshot(),
	})
}

func (s *Server) handleScraperStop(w http.ResponseWriter, r *http.Request) {
	scraperRT.mu.Lock()
	cancel := scraperRT.cancelRun
	scraperRT.mu.Unlock()
	if cancel != nil {
		cancel()
		appendScraperLog("warn", "Online proxy scrape stopped by operator.")
	}
	writeJSON(w, http.StatusOK, s.scraperStatusSnapshot())
}

func (s *Server) handleScraperClear(w http.ResponseWriter, r *http.Request) {
	if ppV2 != nil && ppV2.Pool != nil {
		_ = ppV2.Pool.ReplaceManagedPrefixProxies(scrapedProxyPrefix, nil, false)
		s.syncProxyPoolNow()
	}
	scraperRT.mu.Lock()
	scraperRT.logs = nil
	scraperRT.addedToPool = 0
	scraperRT.mu.Unlock()
	appendScraperLog("info", "Cleared all scraped proxies from Proxy Pool and reset log.")
	writeJSON(w, http.StatusOK, s.scraperStatusSnapshot())
}

// ============================================================================
// Native Agent Tools for proxy_harvester, auto, pentest, and worker
// ============================================================================

func (s *Server) proxyScraperAgentTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolScrapeOnlineProxies(),
		s.toolListProxyScrapeSources(),
		s.toolAddProxyScrapeSource(),
		s.toolRemoveProxyScrapeSource(),
		s.toolVerifyAndImportScrapedProxies(),
	}
}

func (s *Server) toolScrapeOnlineProxies() actool.CoreTool {
	return wrTool("scrape_online_proxies",
		"Scrape free public SOCKS5 and HTTPS proxies from 16+ curated GitHub & API feeds (plus AI-discovered feeds), verify them with 2-stage TCP + strict TLS certificate & Elite non-transparent IP checks, and import the fastest working proxies into ARTEX's Proxy Pool.",
		objSchema(map[string]any{
			"max_proxies":      map[string]any{"type": "integer", "description": "Optional max verified proxies to add to pool (default 25, max 100)"},
			"max_latency_ms":   map[string]any{"type": "integer", "description": "Optional max HTTPS round-trip latency in ms (default 4500)"},
			"protocols":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Protocols to scrape: [\"socks5\", \"http\"]"},
			"auto_enable_pool": map[string]any{"type": "boolean", "description": "Automatically enable Proxy Pool when verified proxies are added (default true)"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			cfg := s.loadProxyScraperConfig()
			var a struct {
				MaxProxies     *int     `json:"max_proxies"`
				MaxLatencyMS   *int     `json:"max_latency_ms"`
				Protocols      []string `json:"protocols"`
				AutoEnablePool *bool    `json:"auto_enable_pool"`
			}
			_ = json.Unmarshal(in, &a)
			if a.MaxProxies != nil && *a.MaxProxies > 0 {
				cfg.MaxProxies = *a.MaxProxies
			}
			if a.MaxLatencyMS != nil && *a.MaxLatencyMS > 0 {
				cfg.MaxLatencyMS = *a.MaxLatencyMS
			}
			if len(a.Protocols) > 0 {
				cfg.Protocols = a.Protocols
			}
			if a.AutoEnablePool != nil {
				cfg.AutoEnablePool = *a.AutoEnablePool
			}
			_ = s.saveProxyScraperConfig(cfg)
			snap := s.runOnlineScrapeCycle(ctx, false)
			return jsonResult(snap)
		})
}

func (s *Server) toolListProxyScrapeSources() actool.CoreTool {
	return roTool("list_proxy_scrape_sources",
		"List all built-in and AI-discovered online proxy scrape feeds along with their protocol, last candidate count, verified Elite proxy yield, and error status.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			sources := s.loadAllProxyScrapeSources()
			return jsonResult(map[string]any{
				"count":   len(sources),
				"sources": sources,
			})
		})
}

func isNonPublicScrapeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		// Block RFC 6598 CGNAT (100.64.0.0/10) as well as standard private/loopback/link-local ranges
		if ip[0] == 100 && ip[1]&0xc0 == 64 {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast()
}

func validatePublicScrapeFeedURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("valid public http/https URL is required")
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(u.Hostname()), "."))
	if zone := strings.IndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return nil, fmt.Errorf("private/local feed host %q is not allowed", host)
	}
	ip := net.ParseIP(host)
	if ip == nil && repeaterLooksNumericHost(host) {
		var ok bool
		ip, ok = repeaterParseLegacyIPv4(host)
		if !ok {
			return nil, fmt.Errorf("numeric host address %q rejected", host)
		}
	}
	if ip != nil && isNonPublicScrapeIP(ip) {
		return nil, fmt.Errorf("private, loopback, or metadata IP %s is not allowed for proxy scrape feeds", ip)
	}
	return u, nil
}

func scraperBlockNonPublicDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || isNonPublicScrapeIP(ip) {
		return fmt.Errorf("blocked non-public dial address %s for proxy scrape feed", host)
	}
	return nil
}

func newSafePublicFeedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 15 * time.Second,
				Control:   scraperBlockNonPublicDial,
			}).DialContext,
		},
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			_, err := validatePublicScrapeFeedURL(next.URL.String())
			return err
		},
	}
}

func (s *Server) toolAddProxyScrapeSource() actool.CoreTool {
	return wrTool("add_proxy_scrape_source",
		"Register a newly discovered online proxy feed URL (raw GitHub TXT, CSV, JSON, or public proxy API) into ARTEX's persistent Online Proxy Scraper registry and optionally test & verify its proxies immediately.",
		objSchema(map[string]any{
			"name":             strParam("Descriptive source name (e.g. 'owner/repo SOCKS5 live list')"),
			"url":              strParam("Direct HTTP/HTTPS URL returning proxy ip:port entries in TXT, JSON, CSV, or HTML"),
			"protocol":         strParam("Default protocol for bare ip:port entries: socks5 | http"),
			"priority":         map[string]any{"type": "boolean", "description": "True if this source provides pre-checked/fresh proxies that should be verified first"},
			"test_immediately": map[string]any{"type": "boolean", "description": "Immediately fetch, 2-stage verify, and import working proxies from this source (default true)"},
		}, "name", "url", "protocol"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name            string `json:"name"`
				URL             string `json:"url"`
				Protocol        string `json:"protocol"`
				Priority        bool   `json:"priority"`
				TestImmediately *bool  `json:"test_immediately"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			u, err := validatePublicScrapeFeedURL(a.URL)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			proto := strings.ToLower(strings.TrimSpace(a.Protocol))
			if proto != "socks5" && proto != "http" {
				proto = "socks5"
			}

			existing := s.loadAllProxyScrapeSources()
			for _, ex := range existing {
				if strings.EqualFold(ex.URL, u.String()) {
					return jsonResult(map[string]any{"added": false, "reason": "URL already registered", "source": ex})
				}
			}

			var custom []ProxyScrapeSource
			if s != nil && s.m != nil && s.m.pg != nil {
				if raw, ok, _ := s.m.pg.GetSetting(settingProxyScraperSources); ok && raw != "" {
					_ = json.Unmarshal([]byte(raw), &custom)
				}
			}
			newSrc := ProxyScrapeSource{
				ID:           "ai-src-" + randomShortHex(4),
				Name:         strings.TrimSpace(a.Name),
				URL:          u.String(),
				Protocol:     proto,
				Priority:     a.Priority,
				Builtin:      false,
				AddedByAgent: true,
				Enabled:      true,
			}
			custom = append(custom, newSrc)
			if err := s.saveCustomProxyScrapeSources(custom); err != nil {
				return actool.Errorf("save source failed: " + err.Error()), nil
			}
			appendScraperLog("ai", fmt.Sprintf("[AI-HARVESTER] Registered new %s proxy feed: %s (%s)", strings.ToUpper(proto), newSrc.Name, newSrc.URL))

			testNow := a.TestImmediately == nil || *a.TestImmediately
			verifiedCount := 0
			candCount := 0
			if testNow {
				cl := newSafePublicFeedClient(8 * time.Second)
				if resp, ferr := cl.Get(newSrc.URL); ferr == nil {
					b, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
					_ = resp.Body.Close()
					cands := extractProxiesFromBody(string(b), proto, newSrc.ID, true)
					candCount = len(cands)
					if len(cands) > 80 {
						cands = cands[:80]
					}
					if len(cands) > 0 {
						selfIP := resolveSelfPublicIP(ctx)
						cfg := s.loadProxyScraperConfig()
						verified := s.verifyAndImportCandidates(ctx, cands, selfIP, cfg)
						verifiedCount = len(verified)
					}
				}
			}

			return jsonResult(map[string]any{
				"added":               true,
				"source":              newSrc,
				"candidates_extracted": candCount,
				"verified_imported":   verifiedCount,
			})
		})
}

func (s *Server) toolRemoveProxyScrapeSource() actool.CoreTool {
	return wrTool("remove_proxy_scrape_source",
		"Remove a dead or zero-yield custom proxy scrape source by source_id.",
		objSchema(map[string]any{
			"source_id": strParam("Source ID from list_proxy_scrape_sources (custom ai-src-* sources)"),
		}, "source_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				SourceID string `json:"source_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			targetID := strings.TrimSpace(a.SourceID)
			var custom []ProxyScrapeSource
			if s != nil && s.m != nil && s.m.pg != nil {
				if raw, ok, _ := s.m.pg.GetSetting(settingProxyScraperSources); ok && raw != "" {
					_ = json.Unmarshal([]byte(raw), &custom)
				}
			}
			var kept []ProxyScrapeSource
			removed := false
			for _, c := range custom {
				if c.ID == targetID {
					removed = true
					continue
				}
				kept = append(kept, c)
			}
			if removed {
				_ = s.saveCustomProxyScrapeSources(kept)
				appendScraperLog("ai", fmt.Sprintf("[AI-HARVESTER] Pruned dead custom proxy source %s", targetID))
			}
			return jsonResult(map[string]any{"removed": removed, "source_id": targetID})
		})
}

func (s *Server) toolVerifyAndImportScrapedProxies() actool.CoreTool {
	return wrTool("verify_and_import_scraped_proxies",
		"Run ARTEX's strict 2-stage TCP + HTTPS certificate + Elite non-transparent IP verification on raw proxy candidates extracted by the agent and import only fast, verified working proxies into Proxy Pool.",
		objSchema(map[string]any{
			"proxies":          strParam("Raw text or JSON containing ip:port or scheme://ip:port candidates"),
			"default_protocol": strParam("Protocol for bare ip:port entries: socks5 (default) | http"),
		}, "proxies"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Proxies         string `json:"proxies"`
				DefaultProtocol string `json:"default_protocol"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			proto := strings.ToLower(strings.TrimSpace(a.DefaultProtocol))
			if proto != "http" && proto != "socks5" {
				proto = "socks5"
			}
			cands := extractProxiesFromBody(a.Proxies, proto, "ai-harvester-direct", true)
			if len(cands) == 0 {
				return jsonResult(map[string]any{"candidates": 0, "verified": 0})
			}
			if len(cands) > 150 {
				cands = cands[:150]
			}
			appendScraperLog("ai", fmt.Sprintf("[AI-HARVESTER] Verifying %d agent-extracted %s proxy candidates...", len(cands), strings.ToUpper(proto)))
			selfIP := resolveSelfPublicIP(ctx)
			cfg := s.loadProxyScraperConfig()
			verified := s.verifyAndImportCandidates(ctx, cands, selfIP, cfg)
			return jsonResult(map[string]any{
				"candidates_checked": len(cands),
				"verified_imported":  len(verified),
				"verified":           verified,
			})
		})
}
