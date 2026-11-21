package proxyv2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// TestProxy tests a single proxy and returns detailed results.
// Inspired by ProfGinx_custom's TestProxy() method.
func (p *Pool) TestProxy(id string) (*TestResult, error) {
	p.state.mu.RLock()
	var target *ProxyInfo
	for i := range p.state.proxies {
		if p.state.proxies[i].ID == id {
			cp := p.state.proxies[i]
			target = &cp
			break
		}
	}
	p.state.mu.RUnlock()

	if target == nil {
		return nil, fmt.Errorf("proxy not found: %s", id)
	}

	success, originIP, latencyMs, probeErr := testProxyDirect(target)

	// Geo lookup on success
	var country, city string
	if success && originIP != "" {
		country, city, _ = lookupGeoIP(originIP)
	}

	// Update proxy state (preserve manual Disabled status if the proxy was disabled!)
	p.state.mu.Lock()
	for i := range p.state.proxies {
		if p.state.proxies[i].ID == id {
			wasDisabled := !p.state.proxies[i].Active || p.state.proxies[i].Status == StatusDisabled
			p.state.proxies[i].LastChecked = time.Now()
			p.state.proxies[i].Latency = time.Duration(latencyMs) * time.Millisecond
			p.state.proxies[i].LatencyMS = latencyMs
			if success {
				if !wasDisabled {
					p.state.proxies[i].Active = true
					p.state.proxies[i].Status = StatusHealthy
				}
				p.state.proxies[i].ConsecutiveFailures = 0
				p.state.proxies[i].SuccessRate = p.state.proxies[i].SuccessRate*0.9 + 0.1 // EMA
				p.state.proxies[i].ResponseIP = originIP
				if country != "" {
					p.state.proxies[i].Country = country
				}
				if city != "" {
					p.state.proxies[i].City = city
				}
			} else {
				if !wasDisabled {
					p.state.proxies[i].Status = StatusUnhealthy
				}
				p.state.proxies[i].ConsecutiveFailures++
				p.state.proxies[i].SuccessRate *= 0.9 // Decay
			}
			break
		}
	}
	_ = p.persistLocked()
	p.state.mu.Unlock()

	return &TestResult{
		ProxyID: id, Success: success,
		Latency:    time.Duration(latencyMs) * time.Millisecond,
		LatencyMS:  latencyMs,
		ResponseIP: originIP, Country: country, City: city,
		Error:     probeErr,
		CheckedAt: time.Now(),
	}, nil
}

// TestAllProxies concurrently tests all proxies in the pool and selects the
// lowest-latency healthy proxy if the current active proxy is missing or unhealthy.
func (p *Pool) TestAllProxies(ctx context.Context) ([]TestResult, error) {
	p.state.mu.RLock()
	ids := make([]string, len(p.state.proxies))
	for i, px := range p.state.proxies {
		ids[i] = px.ID
	}
	conc := p.state.config.ConcurrentTests
	p.state.mu.RUnlock()
	if conc <= 0 {
		conc = 10
	}

	results := make([]TestResult, len(ids))
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)

	for i, id := range ids {
		wg.Add(1)
		go func(idx int, pid string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := p.TestProxy(pid)
			if err != nil {
				results[idx] = TestResult{ProxyID: pid, Error: err.Error()}
				return
			}
			results[idx] = *result
		}(i, id)
	}
	wg.Wait()

	// Only auto-select or failover activeID when Pool Routing is already explicitly
	// enabled AND an active proxy was previously in use (failed during testing).
	// Importing or testing proxies when Pool is disabled (or when no proxy is in use)
	// must NEVER automatically mark a proxy "In Use"!
	p.state.mu.Lock()
	if p.state.config != nil && p.state.config.Enabled && p.state.activeID != "" {
		activeHealthy := false
		for _, px := range p.state.proxies {
			if px.ID == p.state.activeID && px.Active && px.Status == StatusHealthy {
				activeHealthy = true
				break
			}
		}
		if !activeHealthy {
			p.state.activeID = p.pickBestHealthyOrActiveLocked()
		}
	}
	_ = p.persistLocked()
	p.state.mu.Unlock()

	return results, nil
}

// testProxyDirect performs an actual HTTPS tunnel test through a proxy across
// reliable global IP-echo endpoints so temporary upstream 5xxs don't false-fail.
func testProxyDirect(px *ProxyInfo) (bool, string, int64, string) {
	proxyURLStr := px.buildProxyURL()
	parsed, err := url.Parse(proxyURLStr)
	if err != nil {
		return false, "", 0, err.Error()
	}

	var client *http.Client
	switch px.Type {
	case ProxyTypeSOCKS4, ProxyTypeSOCKS5, ProxyTypeSOCKS5H:
		dialer, err := proxy.FromURL(parsed, proxy.Direct)
		if err != nil {
			return false, "", 0, err.Error()
		}
		transport := &http.Transport{Dial: dialer.Dial}
		defer transport.CloseIdleConnections()
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	default:
		transport := &http.Transport{Proxy: http.ProxyURL(parsed)}
		defer transport.CloseIdleConnections()
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}

	endpoints := []string{
		"https://api.ipify.org?format=json",
		"https://checkip.amazonaws.com",
		"https://httpbin.org/ip",
	}
	var lastErr string
	for _, testURL := range endpoints {
		start := time.Now()
		resp, err := client.Get(testURL)
		lat := time.Since(start).Milliseconds()
		if err != nil {
			lastErr = err.Error()
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Sprintf("HTTP %d from %s", resp.StatusCode, testURL)
			continue
		}
		if rerr != nil {
			return true, "", lat, ""
		}
		var ipResp struct {
			IP     string `json:"ip"`
			Origin string `json:"origin"`
		}
		if json.Unmarshal(body, &ipResp) == nil {
			if ipResp.IP != "" {
				return true, strings.TrimSpace(ipResp.IP), lat, ""
			}
			if ipResp.Origin != "" {
				origin, _, _ := strings.Cut(ipResp.Origin, ",")
				return true, strings.TrimSpace(origin), lat, ""
			}
		}
		plain := strings.TrimSpace(string(body))
		if len(plain) <= 64 && !strings.Contains(plain, "<") {
			return true, plain, lat, ""
		}
		return true, "", lat, ""
	}
	return false, "", 0, lastErr
}

// lookupGeoIP fetches geographic location for an IP address.
// Inspired by ProfGinx_custom's lookupProxyGeo().
// Returns: country name, city, country code.
func lookupGeoIP(ip string) (string, string, string) {
	// Strip port if present
	if idx := strings.Index(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Skip local IPs
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") || ip == "::1" || ip == "localhost" {
		return "Local", "", ""
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Try ip-api.com first (free, 45 req/min)
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s", ip))
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		var geo struct {
			Country     string `json:"country"`
			City        string `json:"city"`
			CountryCode string `json:"countryCode"`
		}
		if json.NewDecoder(resp.Body).Decode(&geo) == nil && geo.Country != "" {
			return geo.Country, geo.City, geo.CountryCode
		}
	}

	// Fallback to ipapi.co
	resp2, err := client.Get(fmt.Sprintf("https://ipapi.co/%s/json/", ip))
	if err == nil && resp2.StatusCode == http.StatusOK {
		defer resp2.Body.Close()
		var geo struct {
			CountryName string `json:"country_name"`
			CountryCode string `json:"country_code"`
			City        string `json:"city"`
		}
		if json.NewDecoder(resp2.Body).Decode(&geo) == nil {
			return geo.CountryName, geo.City, geo.CountryCode
		}
	}

	return "Unknown", "", ""
}
