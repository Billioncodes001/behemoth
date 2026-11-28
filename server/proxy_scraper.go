package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
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

	"github.com/Autumn-27/behemoth/db"
	proxyv2 "github.com/Autumn-27/behemoth/server/proxy/v2"
	actool "github.com/Autumn-27/norma/tool"
	"golang.org/x/net/proxy"
)

const (
	scrapedProxyPrefix            = "scraped-"
	settingProxyScraperConfig     = "proxy_scraper_config_v1"
	settingProxyScraperSources    = "proxy_scraper_sources_v1"
	settingProxyScraperV2Migrated = "proxy_scraper_http_us_v2"
	maxScraperLogEntries          = 300
	defaultScrapeIntervalMinutes  = 30
	defaultScrapeMaxProxies       = 25
	defaultScrapeMaxLatencyMS     = 4500
	defaultMaxCandidatesToCheck   = 600
)

type ProxyScraperConfig struct {
	Enabled          bool     `json:"enabled"`
	AIAgentEnabled   bool     `json:"ai_agent_enabled"`
	AutoEnablePool   bool     `json:"auto_enable_pool"`
	IntervalMinutes  int      `json:"interval_minutes"`
	MaxProxies       int      `json:"max_proxies"`
	MaxLatencyMS     int      `json:"max_latency_ms"`
	Protocols        []string `json:"protocols"`                   // ["http"], ["http","socks5"], or ["socks5"]
	CountryMode      string   `json:"country_mode"`                // "us_preferred" (default) | "us_only" | "all"
	WebshareAPIKey   string   `json:"webshare_api_key,omitempty"`  // optional free-tier Webshare API token (masked in status)
	WebshareKeySaved bool     `json:"webshare_key_saved,omitempty"` // read-only indicator for UI
}

type ProxyScrapeSource struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	Protocol       string `json:"protocol"`                  // "http" | "socks5"
	CountryHint    string `json:"country_hint,omitempty"`    // e.g. "US" for US-specific feeds
	MultiProtocol  bool   `json:"multi_protocol,omitempty"`  // true when feed lines carry explicit http:// or socks5:// schemes
	Priority       bool   `json:"priority"`                  // true = pre-checked/fast/US/premium-free feed checked first
	Builtin        bool   `json:"builtin"`
	AddedByAgent   bool   `json:"added_by_agent,omitempty"`
	Enabled        bool   `json:"enabled"`
	LastCandidates int    `json:"last_candidates"`
	LastVerified   int    `json:"last_verified"`
	LastHTTPStatus int    `json:"last_http_status,omitempty"`
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
	usVerified      int
	httpVerified    int
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
	// --- Tier 1: Premium Proxy Providers' Daily Free Lists & Live US Crawlers (HTTP/HTTPS CONNECT) ---
	{
		ID: "iproyal-free-daily", Name: "IPRoyal Daily Free Proxies (Premium Provider · HTTP/HTTPS)",
		URL:      "https://iproyal.com/free-proxy-list/?entries=100",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "fineproxy-free-daily", Name: "FineProxy Daily Free Proxies (Premium Provider · HTTP/HTTPS)",
		URL:      "https://fineproxy.org/free-proxies/",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxyscrape-v4-us-http", Name: "ProxyScrape v4 Live API (United States · HTTP/SSL)",
		URL:         "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=json&country=us&protocol=http&timeout=5000",
		Protocol:    "http",
		CountryHint: "US", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "geonode-us-http", Name: "GeoNode Live API (United States · Elite/Anon HTTP/S)",
		URL:         "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&country=US&protocols=http%2Chttps",
		Protocol:    "http",
		CountryHint: "US", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "usproxy-html-live", Name: "US-Proxy / Free-Proxy-List (United States Live HTML Table)",
		URL:         "https://free-proxy-list.net/us-proxy.html",
		Protocol:    "http",
		CountryHint: "US", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxynova-us-live", Name: "ProxyNova Live JS-Decoded Crawler (United States HTTP)",
		URL:         "https://www.proxynova.com/proxy-server-list/country-us/",
		Protocol:    "http",
		CountryHint: "US", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxyscrape-shard-us-https", Name: "ProxyScrape CDN Shard (United States HTTPS · 5m)",
		URL:         "https://cdn.jsdelivr.net/gh/ProxyScrape/free-proxy-list@main/proxies/countries/us/https/data.txt",
		Protocol:    "http",
		CountryHint: "US", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxyscrape-shard-us-http", Name: "ProxyScrape CDN Shard (United States HTTP · 5m)",
		URL:         "https://cdn.jsdelivr.net/gh/ProxyScrape/free-proxy-list@main/proxies/countries/us/http/data.txt",
		Protocol:    "http",
		CountryHint: "US", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxifly-us-shard", Name: "Proxifly Live Country Shard (United States · 5m)",
		URL:           "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/US/data.txt",
		Protocol:      "http",
		CountryHint:   "US",
		MultiProtocol: true, Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "fusionproxies-us-shard", Name: "FusionProxies Merged Country Shard (United States · 30m)",
		URL:           "https://raw.githubusercontent.com/FusionProxies/free-proxy-list/main/proxies/countries/US.txt",
		Protocol:      "http",
		CountryHint:   "US",
		MultiProtocol: true, Priority: true, Builtin: true, Enabled: true,
	},

	// --- Tier 2: Active Global HTTP/HTTPS CONNECT Crawlers & JSON APIs ---
	{
		ID: "sslproxies-html-live", Name: "SSLProxies / Free-Proxy-List (Live HTTPS Table)",
		URL:      "https://free-proxy-list.net/ssl-proxy.html",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "freeproxylist-main-live", Name: "Free-Proxy-List.net (Live Elite/Anonymous HTTP Table)",
		URL:      "https://free-proxy-list.net/",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "spysme-http-live", Name: "Spys.me Live Crawler Feed (HTTP/SSL + Country Tags)",
		URL:      "https://spys.me/proxy.txt",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "geonode-global-http", Name: "GeoNode Live API (Global Fast Elite/Anon HTTP/S)",
		URL:      "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxyscrape-v4-http-elite", Name: "ProxyScrape v4 Live API (Global Elite/Anon HTTP/S)",
		URL:      "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=json&protocol=http&anonymity=elite,anonymous&timeout=4500",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "roundproxies-api", Name: "RoundProxies Live JSON API (Checked HTTP/S)",
		URL:      "https://roundproxies.com/api/get-free-proxies/?limit=50&page=1&sort_by=lastChecked&sort_type=desc",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxyscrape-https-elite", Name: "ProxyScrape API v2 (HTTPS · Elite/Anonymous)",
		URL:      "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=4500&ssl=yes&anonymity=elite,anonymous",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "monosans-http", Name: "monosans/proxy-list (HTTP · Hourly Speed-Sorted)",
		URL:      "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxifly-http", Name: "proxifly/free-proxy-list (HTTP · 5m Live)",
		URL:      "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "jetkai-https", Name: "jetkai/proxy-list (Online HTTPS)",
		URL:      "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "dinoz0rg-http", Name: "dinoz0rg/proxy-list (Checked HTTP/S)",
		URL:      "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/http.txt",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "vakhov-https", Name: "vakhov/fresh-proxy-list (Verified HTTPS)",
		URL:      "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt",
		Protocol: "http", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "vakhov-http", Name: "vakhov/fresh-proxy-list (Fresh HTTP)",
		URL:      "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
		Protocol: "http", Priority: false, Builtin: true, Enabled: true,
	},
	{
		ID: "hideip-connect", Name: "zloi-user/hideip.me (HTTPS CONNECT · 10m)",
		URL:      "https://raw.githubusercontent.com/zloi-user/hideip.me/main/connect.txt",
		Protocol: "http", Priority: false, Builtin: true, Enabled: true,
	},
	{
		ID: "thespeedx-http", Name: "TheSpeedX/PROXY-List (HTTP)",
		URL:      "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		Protocol: "http", Priority: false, Builtin: true, Enabled: true,
	},

	// --- Tier 3: Optional SOCKS5 Feeds (polled when SOCKS5 is enabled; bridged via local HTTP forwarder) ---
	{
		ID: "monosans-socks5", Name: "monosans/proxy-list (SOCKS5 · Hourly Speed-Sorted)",
		URL:      "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxifly-socks5", Name: "proxifly/free-proxy-list (SOCKS5 · 5m Live)",
		URL:      "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "proxyscrape-socks5", Name: "ProxyScrape API v2 (SOCKS5 · Fast)",
		URL:      "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=4500&country=all",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "jetkai-socks5", Name: "jetkai/proxy-list (Online SOCKS5)",
		URL:      "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "dinoz0rg-socks5", Name: "dinoz0rg/proxy-list (Checked SOCKS5)",
		URL:      "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/socks5.txt",
		Protocol: "socks5", Priority: true, Builtin: true, Enabled: true,
	},
	{
		ID: "elliottophellia-socks5", Name: "elliottophellia/proxylist (Checked SOCKS5)",
		URL:      "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/socks5/global/socks5_checked.txt",
		Protocol: "socks5", Priority: false, Builtin: true, Enabled: true,
	},
	{
		ID: "hideip-socks5", Name: "zloi-user/hideip.me (SOCKS5 · 10m)",
		URL:      "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
		Protocol: "socks5", Priority: false, Builtin: true, Enabled: true,
	},
	{
		ID: "thespeedx-socks5", Name: "TheSpeedX/PROXY-List (SOCKS5)",
		URL:      "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
		Protocol: "socks5", Priority: false, Builtin: true, Enabled: true,
	},
}

var (
	reScrapedAuthSchemeHostPort = regexp.MustCompile(`(?i)\b(socks5h?|socks4a?|https?)://(?:([^:@\s/]+):([^@\s/]+)@)?((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b`)
	reScrapedColonAuth          = regexp.MustCompile(`(?m)^\s*((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5}):([^:\s|]+):([^:\s|]+)\s*$`)
	reScrapedBareHostPort       = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b`)
	reSpysMeLine                = regexp.MustCompile(`(?m)^(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\s+([A-Z]{2})-([NAH!]+)(?:-([S!]+))?`)
	reHTMLTableProxyRow         = regexp.MustCompile(`(?is)<tr[^>]*>\s*<td[^>]*>\s*(\d{1,3}(?:\.\d{1,3}){3})\s*</td>\s*<td[^>]*>\s*(\d{2,5})\s*</td>(?:\s*<td[^>]*>\s*([A-Z]{2})\s*</td>)?(?:\s*<td[^>]*>([^<]*)</td>)?(?:\s*<td[^>]*>([^<]*)</td>)?(?:\s*<td[^>]*>[^<]*</td>)?(?:\s*<td[^>]*>\s*(yes|no)\s*</td>)?`)
	reProxyNovaRow              = regexp.MustCompile(`(?is)document\.write\(([\s\S]*?)\)\s*</script>[\s\S]{0,360}?<td[^>]*>\s*(\d{2,5})\s*</td>`)
	reProxyNovaSubstr           = regexp.MustCompile(`["']([^"']+)["']\s*\.\s*(substring|substr)\s*\(\s*([^,)]+)\s*(?:,\s*([^)]+))?\)`)
	reProxyNovaAtob             = regexp.MustCompile(`atob\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)`)
	reIPRoyalRecord             = regexp.MustCompile(`"ip":\[0,"(\d{1,3}(?:\.\d{1,3}){3})"\],"port":\[0,"(\d{2,5})"\],"protocol":\[0,"([^"]+)"\],"country":\[0,"([^"]+)"\](?:,"city":\[0,"([^"]*)"\])?`)
)

func defaultProxyScraperConfig() ProxyScraperConfig {
	return ProxyScraperConfig{
		Enabled:         false,
		AIAgentEnabled:  true,
		AutoEnablePool:  true,
		IntervalMinutes: defaultScrapeIntervalMinutes,
		MaxProxies:      defaultScrapeMaxProxies,
		MaxLatencyMS:    defaultScrapeMaxLatencyMS,
		Protocols:       []string{"http", "socks5"},
		CountryMode:     "us_preferred",
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
		if (pl == "http" || pl == "socks5") && !seen[pl] {
			seen[pl] = true
			cleanProtos = append(cleanProtos, pl)
		}
	}
	if len(cleanProtos) == 0 {
		cleanProtos = []string{"http"}
	}
	// Always keep "http" ordered ahead of "socks5" when both are selected.
	sort.SliceStable(cleanProtos, func(i, j int) bool {
		return cleanProtos[i] == "http" && cleanProtos[j] != "http"
	})
	cfg.Protocols = cleanProtos

	switch strings.ToLower(strings.TrimSpace(cfg.CountryMode)) {
	case "us_only", "us":
		cfg.CountryMode = "us_only"
	case "all", "global", "any":
		cfg.CountryMode = "all"
	default:
		cfg.CountryMode = "us_preferred"
	}
	cfg.WebshareAPIKey = strings.TrimSpace(cfg.WebshareAPIKey)
	return cfg
}

func (s *Server) loadProxyScraperConfig() ProxyScraperConfig {
	cfg := defaultProxyScraperConfig()
	if s != nil && s.m != nil && s.m.pg != nil {
		if raw, ok, _ := s.m.pg.GetSetting(settingProxyScraperConfig); ok && strings.TrimSpace(raw) != "" {
			_ = json.Unmarshal([]byte(raw), &cfg)
			// One-time seamless migration to HTTP-first + SOCKS5 enabled (75% HTTP / 25% SOCKS5) + US-preferred
			const v3Flag = "proxy_scraper_v3_http_and_socks5"
			if mig, _, _ := s.m.pg.GetSetting(v3Flag); mig != "true" {
				cfg.Protocols = []string{"http", "socks5"}
				if cfg.CountryMode == "" {
					cfg.CountryMode = "us_preferred"
				}
				_ = s.m.pg.SetSetting(settingProxyScraperV2Migrated, "true")
				_ = s.m.pg.SetSetting(v3Flag, "true")
				_ = s.saveProxyScraperConfig(cfg)
			}
		} else {
			_ = s.m.pg.SetSetting(settingProxyScraperV2Migrated, "true")
			_ = s.m.pg.SetSetting("proxy_scraper_v3_http_and_socks5", "true")
		}
	}
	return normalizeScraperConfig(cfg)
}

func (s *Server) saveProxyScraperConfig(cfg ProxyScraperConfig) error {
	if s != nil && s.m != nil && s.m.pg != nil {
		var prev ProxyScraperConfig
		if raw, ok, _ := s.m.pg.GetSetting(settingProxyScraperConfig); ok && strings.TrimSpace(raw) != "" {
			_ = json.Unmarshal([]byte(raw), &prev)
		}
		// Preserve existing Webshare key when UI sends blank/masked placeholder; allow explicit "CLEAR" to wipe.
		if cfg.WebshareAPIKey == "" || cfg.WebshareAPIKey == "***" {
			cfg.WebshareAPIKey = prev.WebshareAPIKey
		} else if strings.EqualFold(cfg.WebshareAPIKey, "CLEAR") {
			cfg.WebshareAPIKey = ""
		}
	}
	cfg = normalizeScraperConfig(cfg)
	cfg.WebshareKeySaved = false
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_ = s.m.pg.SetSetting(settingProxyScraperV2Migrated, "true")
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
			src.LastHTTPStatus = st.LastHTTPStatus
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
	Username string
	Password string
	Country  string // ISO-3166 alpha-2 (e.g. "US") or country name when known from feed
	City     string
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

func normalizeCountryISO(c string) string {
	v := strings.ToUpper(strings.TrimSpace(c))
	switch v {
	case "US", "USA", "UNITED STATES", "UNITED STATES OF AMERICA":
		return "US"
	case "GB", "UK", "UNITED KINGDOM", "GREAT BRITAIN":
		return "GB"
	case "CA", "CANADA":
		return "CA"
	case "DE", "GERMANY":
		return "DE"
	case "NL", "NETHERLANDS":
		return "NL"
	case "FR", "FRANCE":
		return "FR"
	case "SG", "SINGAPORE":
		return "SG"
	case "JP", "JAPAN":
		return "JP"
	}
	if len(v) == 2 && v[0] >= 'A' && v[0] <= 'Z' && v[1] >= 'A' && v[1] <= 'Z' {
		return v
	}
	return strings.TrimSpace(c)
}

func isUnitedStatesCountry(c string) bool {
	return normalizeCountryISO(c) == "US"
}

func evalSimpleJSIntExpr(expr string) (int, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return 0, false
	}
	if strings.Contains(expr, "-") {
		parts := strings.Split(expr, "-")
		if len(parts) == 2 {
			a, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil {
				return a - b, true
			}
		}
	}
	if strings.Contains(expr, "+") {
		parts := strings.Split(expr, "+")
		if len(parts) == 2 {
			a, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil {
				return a + b, true
			}
		}
	}
	n, err := strconv.Atoi(expr)
	return n, err == nil
}

// decodeProxyNovaWriteExpr decodes ProxyNova's obfuscated JS IP expressions, e.g.:
//   "295711847.89.159.2122957118".substring(13-6, 21-1)
//   "NDIuMTIzLjQ1LjY3".atob / atob("...") + ".12.34"
func decodeProxyNovaWriteExpr(expr string) string {
	var b strings.Builder
	parts := strings.Split(expr, "+")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if m := reProxyNovaSubstr.FindStringSubmatch(part); len(m) >= 4 {
			lit := m[1]
			op := strings.ToLower(m[2])
			arg1, ok1 := evalSimpleJSIntExpr(m[3])
			if !ok1 || arg1 < 0 {
				arg1 = 0
			}
			if arg1 > len(lit) {
				arg1 = len(lit)
			}
			if m[4] == "" {
				b.WriteString(lit[arg1:])
				continue
			}
			arg2, ok2 := evalSimpleJSIntExpr(m[4])
			if !ok2 {
				continue
			}
			if op == "substr" {
				end := arg1 + arg2
				if end > len(lit) {
					end = len(lit)
				}
				if end >= arg1 {
					b.WriteString(lit[arg1:end])
				}
			} else { // substring
				start, end := arg1, arg2
				if start > end {
					start, end = end, start
				}
				if start < 0 {
					start = 0
				}
				if end > len(lit) {
					end = len(lit)
				}
				if end >= start {
					b.WriteString(lit[start:end])
				}
			}
			continue
		}
		if m := reProxyNovaAtob.FindStringSubmatch(part); len(m) >= 2 {
			if dec, err := base64.StdEncoding.DecodeString(m[1]); err == nil {
				b.Write(dec)
				continue
			}
		}
		trimmed := strings.Trim(part, `"' `)
		b.WriteString(trimmed)
	}
	cand := strings.TrimSpace(b.String())
	if ip := net.ParseIP(cand); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	if m := reScrapedBareHostPort.FindStringSubmatch(cand + ":80"); len(m) >= 2 {
		if ip := net.ParseIP(m[1]); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

func jsonPortString(raw any) string {
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.Itoa(int(v))
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func extractProxiesFromBody(body, defaultProto, sourceID string, priority bool) []rawCandidateProxy {
	return extractProxiesFromBodyWithHint(body, defaultProto, "", sourceID, priority, nil)
}

// extractProxiesFromBodyWithHint parses 8 live proxy formats (GeoNode JSON, ProxyScrape v4 JSON,
// IPRoyal Astro SSR daily free list, Webshare REST API JSON, ProxyNova JS-obfuscated HTML,
// Spys.me country-tagged feed, HTML <tr><td> tables, and scheme/bare ip:port lists).
func extractProxiesFromBodyWithHint(body, defaultProto, countryHint, sourceID string, priority bool, allowedProtos map[string]bool) []rawCandidateProxy {
	var out []rawCandidateProxy
	seen := map[string]bool{}
	normHint := normalizeCountryISO(countryHint)
	markRejected := func(host, portStr string) {
		p, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || p < 1 || p > 65535 {
			return
		}
		h := strings.TrimSpace(host)
		seen["http://"+h+":"+strconv.Itoa(p)] = true
		seen["socks5://"+h+":"+strconv.Itoa(p)] = true
	}

	add := func(proto, host, portStr, user, pass, country, city string, prio bool) {
		p, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || p < 1 || p > 65535 {
			return
		}
		host = strings.TrimSpace(host)
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return
		}
		pl := strings.ToLower(strings.TrimSpace(proto))
		switch {
		case strings.HasPrefix(pl, "socks4"):
			return // skip legacy SOCKS4 entries that lack full DNS/TLS CONNECT parity
		case strings.HasPrefix(pl, "socks5"):
			pl = "socks5"
		case pl == "http" || pl == "https" || pl == "ssl" || pl == "connect":
			pl = "http"
		default:
			pl = strings.ToLower(strings.TrimSpace(defaultProto))
			if pl != "socks5" {
				pl = "http"
			}
		}
		if len(allowedProtos) > 0 && !allowedProtos[pl] {
			return
		}
		cc := normalizeCountryISO(country)
		if cc == "" {
			cc = normHint
		}
		key := pl + "://" + host + ":" + strconv.Itoa(p)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, rawCandidateProxy{
			Protocol: pl,
			Host:     host,
			Port:     p,
			Username: strings.TrimSpace(user),
			Password: strings.TrimSpace(pass),
			Country:  cc,
			City:     strings.TrimSpace(city),
			SourceID: sourceID,
			Priority: prio,
		})
	}

	// 1. Premium Provider: IPRoyal Daily Free Proxy List (Astro SSR HTML-escaped JSON records)
	if strings.Contains(body, `"records":[1,`) || strings.Contains(body, `&quot;records&quot;:[1,`) {
		unescaped := html.UnescapeString(body)
		for _, m := range reIPRoyalRecord.FindAllStringSubmatch(unescaped, 500) {
			city := ""
			if len(m) >= 6 {
				city = m[5]
			}
			add(m[3], m[1], m[2], "", "", m[4], city, true)
		}
	}

	// 2. Structured JSON APIs: GeoNode, ProxyScrape v4, Webshare REST API, RoundProxies, PubProxy, SCDN
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var parsedAny any
		if json.Unmarshal([]byte(trimmed), &parsedAny) == nil {
			var items []any
			switch root := parsedAny.(type) {
			case []any:
				items = root
			case map[string]any:
				for _, k := range []string{"data", "proxies", "results", "items"} {
					if arr, ok := root[k].([]any); ok && len(arr) > 0 {
						items = arr
						break
					}
				}
				if tbl, ok := root["table_html"].(string); ok && tbl != "" {
					body += "\n<table>" + tbl + "</table>"
				}
			}
			for _, rawItem := range items {
				obj, ok := rawItem.(map[string]any)
				if !ok {
					continue
				}
				ipStr, _ := obj["ip"].(string)
				if ipStr == "" {
					ipStr, _ = obj["proxy_address"].(string)
				}
				portStr := jsonPortString(obj["port"])
				if portStr == "" {
					if portsMap, ok := obj["ports"].(map[string]any); ok {
						portStr = jsonPortString(portsMap["http"])
					}
				}
				anon, _ := obj["anonymityLevel"].(string)
				if anon == "" {
					anon, _ = obj["anonymity"].(string)
				}
				if strings.EqualFold(strings.TrimSpace(anon), "transparent") {
					markRejected(ipStr, portStr)
					continue
				}
				userStr, _ := obj["username"].(string)
				passStr, _ := obj["password"].(string)
				countryStr, _ := obj["country"].(string)
				if countryStr == "" {
					countryStr, _ = obj["country_code"].(string)
				}
				cityStr, _ := obj["city"].(string)
				if cityStr == "" {
					cityStr, _ = obj["city_name"].(string)
				}
				if ipData, ok := obj["ip_data"].(map[string]any); ok {
					if cc, _ := ipData["countryCode"].(string); cc != "" {
						countryStr = cc
					}
					if ct, _ := ipData["city"].(string); ct != "" && cityStr == "" {
						cityStr = ct
					}
				}
				var protos []string
				if pArr, ok := obj["protocols"].([]any); ok {
					for _, pv := range pArr {
						if ps, ok := pv.(string); ok && ps != "" {
							protos = append(protos, ps)
						}
					}
				} else if ps, ok := obj["protocol"].(string); ok && ps != "" {
					protos = append(protos, ps)
				} else if ps, ok := obj["type"].(string); ok && ps != "" {
					protos = append(protos, ps)
				}
				if len(protos) == 0 {
					protos = []string{defaultProto}
				}
				for _, pr := range protos {
					add(pr, ipStr, portStr, userStr, passStr, countryStr, cityStr, priority || userStr != "")
				}
			}
		}
	}

	// 3. ProxyNova JS-Obfuscated Table Rows (document.write("...".substring(a-b, c-d)))
	if strings.Contains(body, "document.write(") {
		for _, m := range reProxyNovaRow.FindAllStringSubmatch(body, 500) {
			if decIP := decodeProxyNovaWriteExpr(m[1]); decIP != "" {
				add("http", decIP, m[2], "", "", normHint, "", true)
			}
		}
	}

	// 4. Spys.me Annotated Lines (e.g. "198.51.100.7:8080 US-H-S +")
	for _, m := range reSpysMeLine.FindAllStringSubmatch(body, 2000) {
		anonFlag := m[4]
		if strings.HasPrefix(anonFlag, "N") {
			markRejected(m[1], m[2])
			continue // skip non-anonymous / transparent proxies
		}
		hasSSL := len(m) >= 6 && strings.Contains(m[5], "S")
		add("http", m[1], m[2], "", "", m[3], "", priority || hasSSL || m[3] == "US")
	}

	// 5. HTML Table Rows (free-proxy-list.net, us-proxy.html, ssl-proxy.html, SCDN)
	if strings.Contains(body, "<td") {
		for _, m := range reHTMLTableProxyRow.FindAllStringSubmatch(body, 2000) {
			cc := ""
			if len(m) >= 4 {
				cc = m[3]
			}
			anonCol := ""
			if len(m) >= 6 {
				anonCol = strings.ToLower(strings.TrimSpace(m[5]))
			}
			if strings.Contains(anonCol, "transparent") {
				markRejected(m[1], m[2])
				continue
			}
			sslCol := ""
			if len(m) >= 7 {
				sslCol = strings.ToLower(strings.TrimSpace(m[6]))
			}
			rowPrio := priority || sslCol == "yes" || cc == "US"
			add(defaultProto, m[1], m[2], "", "", cc, "", rowPrio)
		}
	}

	// 6. Explicit scheme://[user:pass@]ip:port and ip:port:user:pass lines
	for _, m := range reScrapedAuthSchemeHostPort.FindAllStringSubmatch(body, 6000) {
		add(m[1], m[4], m[5], m[2], m[3], normHint, "", priority || m[2] != "")
	}
	for _, m := range reScrapedColonAuth.FindAllStringSubmatch(body, 2000) {
		add(defaultProto, m[1], m[2], m[3], m[4], normHint, "", true)
	}

	// 7. Bare ip:port fallback (only when not a JSON object where ip/port were already parsed,
	//    and skip multi-protocol feeds whose lines always carry explicit schemes).
	remaining := reScrapedAuthSchemeHostPort.ReplaceAllString(body, " ")
	for _, m := range reScrapedBareHostPort.FindAllStringSubmatch(remaining, 6000) {
		add(defaultProto, m[1], m[2], "", "", normHint, "", priority)
	}
	return out
}

func (s *Server) fetchWebshareFreeTierCandidates(ctx context.Context, apiKey string, allowedProtos map[string]bool) []rawCandidateProxy {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil
	}
	cl := newSafePublicFeedClient(10 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://proxy.webshare.io/api/v2/proxy/list/?mode=direct&page=1&page_size=100", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Token "+apiKey)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36")
	resp, err := cl.Do(req)
	if err != nil {
		appendScraperLog("warn", "[WEBSHARE] Free-tier API request failed: "+firstLine(err.Error(), 90))
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		appendScraperLog("warn", fmt.Sprintf("[WEBSHARE] Free-tier API returned HTTP %d (verify API key)", resp.StatusCode))
		return nil
	}
	cands := extractProxiesFromBodyWithHint(string(b), "http", "", "webshare-free-tier", true, allowedProtos)
	appendScraperLog("source", fmt.Sprintf("[WEBSHARE] Fetched %d dedicated datacenter HTTP proxies from Webshare API", len(cands)))
	return cands
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

func parseCloudflareTrace(body string) (ip, country string) {
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			ip = strings.TrimSpace(v)
		case "loc":
			country = normalizeCountryISO(v)
		}
	}
	return ip, country
}

// verifyCandidateTwoStage implements a fast 2-stage check with instant GeoIP country resolution:
// Stage 1: Fast raw TCP connect (2.2s) to drop dead hosts immediately.
// Stage 2: Full HTTPS CONNECT fetch with strict TLS certificate verification (InsecureSkipVerify=false),
// Elite/Anonymous exit-IP validation (rejecting transparent proxies where exitIP == selfIP),
// and instant exit-country resolution via Cloudflare's HTTPS trace endpoint.
func verifyCandidateTwoStage(ctx context.Context, cand rawCandidateProxy, selfIP string, maxLatency time.Duration) (verifiedCandidateProxy, bool) {
	addr := net.JoinHostPort(cand.Host, strconv.Itoa(cand.Port))

	// Stage 1: Fast TCP pre-filter
	tcpConn, err := (&net.Dialer{Timeout: 2200 * time.Millisecond}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return verifiedCandidateProxy{}, false
	}
	_ = tcpConn.Close()

	scraperRT.mu.Lock()
	scraperRT.tcpAlive++
	scraperRT.mu.Unlock()

	// Stage 2: Strict TLS HTTPS + Non-Transparent Exit-IP + Exit-Country check
	parsed := &url.URL{
		Scheme: cand.Protocol,
		Host:   addr,
	}
	if cand.Username != "" {
		parsed.User = url.UserPassword(cand.Username, cand.Password)
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
		"https://www.cloudflare.com/cdn-cgi/trace",
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
		body, berr := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if berr != nil || resp.StatusCode != http.StatusOK || lat > maxLatency {
			continue
		}

		var exitIP, exitCountry string
		if strings.Contains(testURL, "cdn-cgi/trace") {
			exitIP, exitCountry = parseCloudflareTrace(string(body))
		} else {
			var jsonIP struct {
				IP string `json:"ip"`
			}
			if json.Unmarshal(body, &jsonIP) == nil && jsonIP.IP != "" {
				exitIP = strings.TrimSpace(jsonIP.IP)
			} else {
				exitIP = strings.TrimSpace(string(body))
			}
		}
		if net.ParseIP(exitIP) == nil {
			continue
		}
		// Reject transparent proxies that expose our server's real outbound IP!
		if selfIP != "" && exitIP == selfIP {
			appendScraperLog("warn", fmt.Sprintf("[REJECTED] %s://%s — transparent proxy leaked host IP", cand.Protocol, addr))
			return verifiedCandidateProxy{}, false
		}
		if exitCountry == "" {
			exitCountry = cand.Country
		}
		return verifiedCandidateProxy{
			rawCandidateProxy: cand,
			ExitIP:            exitIP,
			LatencyMS:         lat.Milliseconds(),
			Country:           exitCountry,
			City:              cand.City,
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

func candidateRankTier(c rawCandidateProxy, countryMode string) int {
	if c.Username != "" {
		return 0 // Dedicated/authenticated free-tier proxies (e.g. Webshare) first
	}
	preferUS := countryMode == "us_preferred" || countryMode == "us_only"
	isUS := isUnitedStatesCountry(c.Country)
	isHTTP := c.Protocol == "http"
	switch {
	case preferUS && isUS && isHTTP && c.Priority:
		return 1
	case preferUS && isUS && isHTTP:
		return 2
	case isHTTP && c.Priority:
		return 3
	case preferUS && isUS && c.Priority:
		return 4
	case isHTTP:
		return 5
	case c.Priority:
		return 6
	default:
		return 7
	}
}

// selectBalancedCandidateBatch enforces US-first + HTTP-first ordering and guarantees
// that when both HTTP and SOCKS5 are enabled, SOCKS5 never starves HTTP candidates.
func selectBalancedCandidateBatch(cands []rawCandidateProxy, cfg ProxyScraperConfig, maxTotal int) []rawCandidateProxy {
	seenKey := make(map[string]bool, len(cands))
	deduped := make([]rawCandidateProxy, 0, len(cands))
	for _, c := range cands {
		if cfg.CountryMode == "us_only" && c.Country != "" && !isUnitedStatesCountry(c.Country) {
			continue
		}
		k := c.Protocol + "://" + c.Host + ":" + strconv.Itoa(c.Port)
		if !seenKey[k] {
			seenKey[k] = true
			deduped = append(deduped, c)
		}
	}
	sort.SliceStable(deduped, func(i, j int) bool {
		return candidateRankTier(deduped[i], cfg.CountryMode) < candidateRankTier(deduped[j], cfg.CountryMode)
	})
	if len(deduped) <= maxTotal {
		return deduped
	}

	hasHTTP, hasSocks := false, false
	for _, p := range cfg.Protocols {
		if p == "http" {
			hasHTTP = true
		}
		if p == "socks5" {
			hasSocks = true
		}
	}
	if !hasHTTP || !hasSocks {
		return deduped[:maxTotal]
	}

	// Reserve up to 75% of the verification budget for HTTP/HTTPS CONNECT proxies
	// and 25% for SOCKS5 backup, filling any unused remainder from the other side.
	httpCap := (maxTotal * 3) / 4
	socksCap := maxTotal - httpCap
	var httpPicked, socksPicked, overflow []rawCandidateProxy
	for _, c := range deduped {
		if c.Protocol == "http" {
			if len(httpPicked) < httpCap {
				httpPicked = append(httpPicked, c)
			} else {
				overflow = append(overflow, c)
			}
		} else {
			if len(socksPicked) < socksCap {
				socksPicked = append(socksPicked, c)
			} else {
				overflow = append(overflow, c)
			}
		}
	}
	out := append(httpPicked, socksPicked...)
	for _, c := range overflow {
		if len(out) >= maxTotal {
			break
		}
		out = append(out, c)
	}
	return out
}

// rawGitHubToJSDelivr converts a raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>
// URL into its equivalent jsDelivr CDN mirror (https://cdn.jsdelivr.net/gh/<owner>/<repo>@<branch>/<path>)
// so proxy feed scraping survives transient raw.githubusercontent.com TLS/reset errors.
func rawGitHubToJSDelivr(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !strings.EqualFold(u.Hostname(), "raw.githubusercontent.com") {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 4 {
		return ""
	}
	owner, repo := parts[0], parts[1]
	branch := parts[2]
	restIdx := 3
	// Handle refs/heads/<branch>/<path> form too
	if branch == "refs" && len(parts) >= 6 && parts[3] == "heads" {
		branch = parts[4]
		restIdx = 5
	}
	if owner == "" || repo == "" || branch == "" || restIdx >= len(parts) {
		return ""
	}
	return fmt.Sprintf("https://cdn.jsdelivr.net/gh/%s/%s@%s/%s", owner, repo, branch, strings.Join(parts[restIdx:], "/"))
}

func (s *Server) runOnlineScrapeCycle(parentCtx context.Context, manual bool) map[string]any {
	scraperRT.mu.Lock()
	if scraperRT.running {
		scraperRT.mu.Unlock()
		return s.scraperStatusSnapshot()
	}
	runCtx, cancel := context.WithTimeout(parentCtx, 3*time.Minute)
	scraperRT.running = true
	scraperRT.phase = "Fetching US, Premium-Free & Live API proxy feeds..."
	scraperRT.sourcesPolled = 0
	scraperRT.candidatesFound = 0
	scraperRT.tcpAlive = 0
	scraperRT.httpsVerified = 0
	scraperRT.usVerified = 0
	scraperRT.httpVerified = 0
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
		if !src.Enabled {
			continue
		}
		if src.MultiProtocol || allowedProto[src.Protocol] {
			activeSources = append(activeSources, src)
		}
	}

	appendScraperLog("info", fmt.Sprintf("Starting online proxy scrape across %d live crawlers & feeds (protocols: %s, country: %s, max keep: %d, max latency: %dms)...",
		len(activeSources), strings.Join(cfg.Protocols, ", "), cfg.CountryMode, cfg.MaxProxies, cfg.MaxLatencyMS))

	selfIP := resolveSelfPublicIP(runCtx)
	if selfIP != "" {
		appendScraperLog("info", "Host IP leak-guard baseline initialized (transparent proxies echoing host IP will be rejected).")
	}

	// Fetch all sources concurrently using SSRF-guarded direct HTTP client
	fetchClient := newSafePublicFeedClient(10 * time.Second)
	var candMu sync.Mutex
	var allRawCands []rawCandidateProxy
	var fwg sync.WaitGroup

	if cfg.WebshareAPIKey != "" {
		fwg.Add(1)
		go func() {
			defer fwg.Done()
			wsCands := s.fetchWebshareFreeTierCandidates(runCtx, cfg.WebshareAPIKey, allowedProto)
			if len(wsCands) > 0 {
				candMu.Lock()
				allRawCands = append(allRawCands, wsCands...)
				candMu.Unlock()
			}
		}()
	}

	for _, src := range activeSources {
		src := src
		fwg.Add(1)
		go func() {
			defer fwg.Done()
			t0 := time.Now()
			fetchOne := func(targetURL string) ([]byte, int, error) {
				req, rerr := http.NewRequestWithContext(runCtx, http.MethodGet, targetURL, nil)
				if rerr != nil {
					return nil, 0, rerr
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/json,text/plain,*/*")
				resp, derr := fetchClient.Do(req)
				if derr != nil {
					return nil, 0, derr
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
				status := resp.StatusCode
				_ = resp.Body.Close()
				return bodyBytes, status, nil
			}

			bodyBytes, statusCode, err := fetchOne(src.URL)
			usedMirror := false
			if (err != nil || statusCode != http.StatusOK) && strings.Contains(strings.ToLower(src.URL), "raw.githubusercontent.com") {
				if mirrorURL := rawGitHubToJSDelivr(src.URL); mirrorURL != "" {
					if mBytes, mStatus, mErr := fetchOne(mirrorURL); mErr == nil && mStatus == http.StatusOK {
						bodyBytes, statusCode, err = mBytes, mStatus, nil
						usedMirror = true
					}
				}
			}
			nowStr := time.Now().UTC().Format(time.RFC3339)
			if err != nil {
				scraperRT.mu.Lock()
				st := scraperRT.sourceStats[src.ID]
				st.ID = src.ID
				st.LastHTTPStatus = statusCode
				st.LastError = firstLine(err.Error(), 120)
				st.LastPolledAt = nowStr
				scraperRT.sourceStats[src.ID] = st
				scraperRT.mu.Unlock()
				appendScraperLog("warn", fmt.Sprintf("[SOURCE] %s failed: %s", src.Name, firstLine(err.Error(), 90)))
				return
			}
			if statusCode != http.StatusOK {
				scraperRT.mu.Lock()
				st := scraperRT.sourceStats[src.ID]
				st.ID = src.ID
				st.LastHTTPStatus = statusCode
				st.LastError = fmt.Sprintf("HTTP %d", statusCode)
				st.LastPolledAt = nowStr
				scraperRT.sourceStats[src.ID] = st
				scraperRT.mu.Unlock()
				appendScraperLog("warn", fmt.Sprintf("[SOURCE] %s returned HTTP %d", src.Name, statusCode))
				return
			}

			bodyStr := string(bodyBytes)
			if src.MultiProtocol {
				// Multi-protocol shards have explicit schemes per line; ignore bare lines that lack a scheme.
				var schemeLines []string
				for _, ln := range strings.Split(bodyStr, "\n") {
					if strings.Contains(ln, "://") {
						schemeLines = append(schemeLines, ln)
					}
				}
				bodyStr = strings.Join(schemeLines, "\n")
			}
			extracted := extractProxiesFromBodyWithHint(bodyStr, src.Protocol, src.CountryHint, src.ID, src.Priority, allowedProto)
			scraperRT.mu.Lock()
			scraperRT.sourcesPolled++
			st := scraperRT.sourceStats[src.ID]
			st.ID = src.ID
			st.LastCandidates = len(extracted)
			st.LastHTTPStatus = statusCode
			st.LastError = ""
			st.LastPolledAt = nowStr
			scraperRT.sourceStats[src.ID] = st
			scraperRT.mu.Unlock()

			mirrorTag := ""
			if usedMirror {
				mirrorTag = " [via jsDelivr CDN]"
			}
			appendScraperLog("source", fmt.Sprintf("[SOURCE] %s%s -> %d proxy candidates (%dms)", src.Name, mirrorTag, len(extracted), time.Since(t0).Milliseconds()))

			candMu.Lock()
			allRawCands = append(allRawCands, extracted...)
			candMu.Unlock()
		}()
	}
	fwg.Wait()

	totalRaw := len(allRawCands)
	deduped := selectBalancedCandidateBatch(allRawCands, cfg, defaultMaxCandidatesToCheck)

	scraperRT.mu.Lock()
	scraperRT.candidatesFound = totalRaw
	scraperRT.phase = fmt.Sprintf("2-Stage TLS + US/Elite verification (%d candidates)...", len(deduped))
	scraperRT.mu.Unlock()

	appendScraperLog("info", fmt.Sprintf("Collected %d raw candidates -> testing top %d prioritized HTTP/US candidates via 2-stage TCP + strict TLS/Cloudflare GeoIP verification...",
		totalRaw, len(deduped)))

	verified := s.verifyAndImportCandidates(runCtx, deduped, selfIP, cfg)

	// Trigger self-improving AI Proxy Harvester agent when enabled and either manual or pool needs more yield!
	if cfg.AIAgentEnabled && (len(verified) < cfg.MaxProxies/2 || manual) {
		go s.launchProxyHarvesterAgentRun(len(verified), cfg.MaxProxies)
	}

	return s.scraperStatusSnapshot()
}

func sortVerifiedProxies(list []verifiedCandidateProxy, countryMode string) {
	preferUS := countryMode == "us_preferred" || countryMode == "us_only"
	sort.SliceStable(list, func(i, j int) bool {
		// 1. Dedicated authenticated free-tier proxies first
		if (list[i].Username != "") != (list[j].Username != "") {
			return list[i].Username != ""
		}
		// 2. United States exit IPs first when us_preferred / us_only
		if preferUS {
			usI := isUnitedStatesCountry(list[i].Country)
			usJ := isUnitedStatesCountry(list[j].Country)
			if usI != usJ {
				return usI
			}
		}
		// 3. HTTP/HTTPS CONNECT preferred over SOCKS5 unless SOCKS5 is >400ms faster
		if list[i].Protocol != list[j].Protocol {
			if list[i].Protocol == "http" && list[i].LatencyMS <= list[j].LatencyMS+400 {
				return true
			}
			if list[j].Protocol == "http" && list[j].LatencyMS <= list[i].LatencyMS+400 {
				return false
			}
		}
		return list[i].LatencyMS < list[j].LatencyMS
	})
}

func (s *Server) verifyAndImportCandidates(ctx context.Context, candidates []rawCandidateProxy, selfIP string, cfg ProxyScraperConfig) []verifiedCandidateProxy {
	maxLat := time.Duration(cfg.MaxLatencyMS) * time.Millisecond
	targetGoal := cfg.MaxProxies * 2
	if cfg.CountryMode == "us_preferred" || cfg.CountryMode == "us_only" {
		targetGoal = cfg.MaxProxies * 3
	}
	var verifiedCount atomic.Int64
	var usCount atomic.Int64

	allowedProto := map[string]bool{}
	for _, p := range cfg.Protocols {
		allowedProto[p] = true
	}

	var resMu sync.Mutex
	var verified []verifiedCandidateProxy
	bySourceVerified := map[string]int{}

	sem := make(chan struct{}, 80)
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
			if vp.Country == "" {
				c, city := lookupQuickGeo(vp.ExitIP)
				vp.Country = normalizeCountryISO(c)
				if vp.City == "" {
					vp.City = city
				}
			}
			isUS := isUnitedStatesCountry(vp.Country)
			if cfg.CountryMode == "us_only" && !isUS {
				return
			}

			resMu.Lock()
			verified = append(verified, vp)
			bySourceVerified[vp.SourceID]++
			resMu.Unlock()

			scraperRT.mu.Lock()
			scraperRT.httpsVerified++
			if isUS {
				scraperRT.usVerified++
			}
			if vp.Protocol == "http" {
				scraperRT.httpVerified++
			}
			scraperRT.mu.Unlock()

			tot := int(verifiedCount.Add(1))
			curUS := int(usCount.Load())
			if isUS {
				curUS = int(usCount.Add(1))
			}
			if cfg.CountryMode == "us_preferred" {
				if curUS >= cfg.MaxProxies && tot >= cfg.MaxProxies*2 {
					cancelChecks()
				} else if tot >= targetGoal {
					cancelChecks()
				}
			} else if tot >= targetGoal {
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

	sortVerifiedProxies(verified, cfg.CountryMode)
	if len(verified) > cfg.MaxProxies {
		verified = verified[:cfg.MaxProxies]
	}

	// Enrich top verified proxies with City GeoIP (when missing) & import into Proxy Pool v2
	if ppV2 != nil && ppV2.Pool != nil && len(verified) > 0 {
		now := time.Now()
		poolEntries := make([]proxyv2.ProxyInfo, 0, len(verified))
		for i := range verified {
			country := verified[i].Country
			city := verified[i].City
			if country == "" || city == "" {
				gc, gcity := lookupQuickGeo(verified[i].ExitIP)
				if country == "" && gc != "" {
					country = normalizeCountryISO(gc)
				}
				if city == "" {
					city = gcity
				}
			}
			if isUnitedStatesCountry(country) {
				country = "US"
			}
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
				Username:    verified[i].Username,
				Password:    verified[i].Password,
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

		// Merge with already-healthy scraped-* proxies whose protocol & country match the
		// current scraper policy (automatically pruning stale SOCKS5 rows when HTTP-only is selected!).
		byHostPort := map[string]proxyv2.ProxyInfo{}
		rawExisting, _, _ := ppV2.Pool.GetRawState()
		for _, ex := range rawExisting {
			if !strings.HasPrefix(ex.ID, scrapedProxyPrefix) || !ex.Active || (ex.Status != proxyv2.StatusHealthy && ex.Status != proxyv2.StatusInUse) {
				continue
			}
			exProto := "http"
			if ex.Type == proxyv2.ProxyTypeSOCKS5 {
				exProto = "socks5"
			}
			if !allowedProto[exProto] {
				continue
			}
			if cfg.CountryMode == "us_only" && !isUnitedStatesCountry(ex.Country) {
				continue
			}
			byHostPort[fmt.Sprintf("%s:%d", ex.Host, ex.Port)] = ex
		}
		for _, np := range poolEntries {
			byHostPort[fmt.Sprintf("%s:%d", np.Host, np.Port)] = np
		}
		merged := make([]proxyv2.ProxyInfo, 0, len(byHostPort))
		for _, item := range byHostPort {
			merged = append(merged, item)
		}
		preferUS := cfg.CountryMode == "us_preferred" || cfg.CountryMode == "us_only"
		sort.SliceStable(merged, func(i, j int) bool {
			if (merged[i].Username != "") != (merged[j].Username != "") {
				return merged[i].Username != ""
			}
			if preferUS {
				usI := isUnitedStatesCountry(merged[i].Country)
				usJ := isUnitedStatesCountry(merged[j].Country)
				if usI != usJ {
					return usI
				}
			}
			if merged[i].Type != merged[j].Type {
				if merged[i].Type == proxyv2.ProxyTypeHTTP && merged[i].LatencyMS <= merged[j].LatencyMS+400 {
					return true
				}
				if merged[j].Type == proxyv2.ProxyTypeHTTP && merged[j].LatencyMS <= merged[i].LatencyMS+400 {
					return false
				}
			}
			return merged[i].LatencyMS < merged[j].LatencyMS
		})
		if len(merged) > cfg.MaxProxies {
			merged = merged[:cfg.MaxProxies]
		}

		_ = ppV2.Pool.ReplaceManagedPrefixProxies(scrapedProxyPrefix, merged, cfg.AutoEnablePool)
		s.syncProxyPoolNow()

		usInPool, httpInPool := 0, 0
		for _, m := range merged {
			if isUnitedStatesCountry(m.Country) {
				usInPool++
			}
			if m.Type == proxyv2.ProxyTypeHTTP {
				httpInPool++
			}
		}
		scraperRT.mu.Lock()
		scraperRT.addedToPool = len(merged)
		scraperRT.mu.Unlock()
		appendScraperLog("summary", fmt.Sprintf("Scrape complete: %d verified Elite proxies active in Pool (%d HTTP/HTTPS, %d US, fastest: %dms).",
			len(merged), httpInPool, usInPool, merged[0].LatencyMS))
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

	cfg := s.loadProxyScraperConfig()
	prompt := fmt.Sprintf(
		"Online Proxy Scraper cycle just finished with %d verified Elite proxies (target pool size: %d, preferred protocols: %s, country mode: %s).\n\n"+
			"Execute your self-improving Proxy Harvester workflow now — PRIORITIZING **HTTP / HTTPS CONNECT** and **United States (US)** proxies (since HTTP proxies work natively with every scanner and web tool, and US exit IPs minimize geo-blocks):\n"+
			"1. Call `list_proxy_scrape_sources` to inspect which feeds produced verified proxies and which failed or returned 0 candidates (remove broken custom feeds with `remove_proxy_scrape_source`).\n"+
			"2. Search GitHub API, premium proxy providers' daily free proxy pages, and live JSON/HTML proxy crawlers (`Bash` curl to `https://api.github.com/search/repositories?q=free+proxy+list+http+us&sort=updated&order=desc`, `multi_engine_search`, `WebFetch`) to discover actively updated **HTTP/HTTPS CONNECT** and **United States (US)** proxy feeds or live provider free-list pages not yet in `list_proxy_scrape_sources`.\n"+
			"3. Register 1–3 high-yield newly discovered HTTP/US feed URLs via `add_proxy_scrape_source` (with `protocol: \"http\"`, `country_hint: \"US\"` when US-specific, `test_immediately: true`), and if you extract proxies from a paginated JSON/HTML/JS-obfuscated provider page via `Bash`/Python, pass them through `verify_and_import_scraped_proxies` (`default_protocol: \"http\"`).\n"+
			"4. Conclude with a concise summary of newly added HTTP/US feeds and verified Elite proxies.",
		lastVerified, targetMax, strings.Join(cfg.Protocols, ","), cfg.CountryMode,
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
	publicCfg := cfg
	publicCfg.WebshareKeySaved = strings.TrimSpace(cfg.WebshareAPIKey) != ""
	publicCfg.WebshareAPIKey = ""
	sources := s.loadAllProxyScrapeSources()
	scraperRT.mu.RLock()
	logsCopy := make([]ProxyScraperLogEntry, len(scraperRT.logs))
	copy(logsCopy, scraperRT.logs)
	out := map[string]any{
		"config":             publicCfg,
		"running":            scraperRT.running,
		"ai_running":         scraperRT.aiRunning,
		"phase":              scraperRT.phase,
		"sources_polled":     scraperRT.sourcesPolled,
		"candidates_found":   scraperRT.candidatesFound,
		"tcp_alive":          scraperRT.tcpAlive,
		"https_verified":     scraperRT.httpsVerified,
		"us_verified":        scraperRT.usVerified,
		"http_verified":      scraperRT.httpVerified,
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
		"Scrape fast HTTP/HTTPS CONNECT and US-preferred proxies from 30+ live crawlers, premium providers' daily free lists (IPRoyal, FineProxy, Webshare), JSON APIs (GeoNode, ProxyScrape v4, RoundProxies), HTML/JS tables (US-Proxy, SSLProxies, ProxyNova, Spys.me), and GitHub shards; verify via 2-stage TCP + strict TLS + Cloudflare exit-country check; and import the fastest working proxies into BEHEMOTH's Proxy Pool.",
		objSchema(map[string]any{
			"max_proxies":      map[string]any{"type": "integer", "description": "Optional max verified proxies to add to pool (default 25, max 100)"},
			"max_latency_ms":   map[string]any{"type": "integer", "description": "Optional max HTTPS round-trip latency in ms (default 4500)"},
			"protocols":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Protocols to scrape: [\"http\"] (default, universally compatible), [\"http\", \"socks5\"], or [\"socks5\"]"},
			"country_mode":     strParam("Country targeting: us_preferred (default: fill United States proxies first, top up with fast global) | us_only (strict US exit IPs only) | all"),
			"auto_enable_pool": map[string]any{"type": "boolean", "description": "Automatically enable Proxy Pool when verified proxies are added (default true)"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			cfg := s.loadProxyScraperConfig()
			var a struct {
				MaxProxies     *int     `json:"max_proxies"`
				MaxLatencyMS   *int     `json:"max_latency_ms"`
				Protocols      []string `json:"protocols"`
				CountryMode    string   `json:"country_mode"`
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
			if strings.TrimSpace(a.CountryMode) != "" {
				cfg.CountryMode = a.CountryMode
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
		"Register a newly discovered online proxy feed or live provider URL (HTTP/HTTPS JSON API, HTML table, TXT, or CSV) into BEHEMOTH's persistent Online Proxy Scraper registry and optionally test & verify its proxies immediately.",
		objSchema(map[string]any{
			"name":             strParam("Descriptive source name (e.g. 'Provider US HTTP live list')"),
			"url":              strParam("Direct HTTP/HTTPS URL returning proxy entries in JSON, HTML table, TXT, or CSV"),
			"protocol":         strParam("Default protocol for bare ip:port entries: http (default) | socks5"),
			"country_hint":     strParam("Optional ISO country code when this feed is country-specific (e.g. 'US')"),
			"priority":         map[string]any{"type": "boolean", "description": "True if this source provides pre-checked/US/fast proxies that should be verified first"},
			"test_immediately": map[string]any{"type": "boolean", "description": "Immediately fetch, 2-stage verify, and import working proxies from this source (default true)"},
		}, "name", "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name            string `json:"name"`
				URL             string `json:"url"`
				Protocol        string `json:"protocol"`
				CountryHint     string `json:"country_hint"`
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
				proto = "http"
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
				CountryHint:  normalizeCountryISO(a.CountryHint),
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
				cl := newSafePublicFeedClient(10 * time.Second)
				if resp, ferr := cl.Get(newSrc.URL); ferr == nil {
					b, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
					_ = resp.Body.Close()
					cands := extractProxiesFromBodyWithHint(string(b), proto, newSrc.CountryHint, newSrc.ID, true, nil)
					candCount = len(cands)
					if len(cands) > 100 {
						cands = cands[:100]
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
				"added":                true,
				"source":               newSrc,
				"candidates_extracted": candCount,
				"verified_imported":    verifiedCount,
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
		"Run BEHEMOTH's strict 2-stage TCP + HTTPS certificate + Cloudflare exit-country + Elite non-transparent IP verification on raw proxy candidates (JSON, HTML, TXT, or ip:port) extracted by the agent and import only fast, verified working proxies into Proxy Pool.",
		objSchema(map[string]any{
			"proxies":          strParam("Raw text, HTML, or JSON containing ip:port, ip:port:user:pass, or scheme://ip:port candidates"),
			"default_protocol": strParam("Protocol for bare ip:port entries: http (default) | socks5"),
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
				proto = "http"
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
