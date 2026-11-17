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

	success, originIP, latencyMs := testProxyDirect(target)

	// Geo lookup on success
	var country, city string
	if success && originIP != "" {
		country, city, _ = lookupGeoIP(originIP)
	}

	// Update proxy state
	p.state.mu.Lock()
	for i := range p.state.proxies {
		if p.state.proxies[i].ID == id {
			p.state.proxies[i].LastChecked = time.Now()
			p.state.proxies[i].Latency = time.Duration(latencyMs) * time.Millisecond
			if success {
				if p.state.proxies[i].Status != StatusDisabled {
					p.state.proxies[i].Active = true
				}
				p.state.proxies[i].Status = StatusHealthy
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
				p.state.proxies[i].Status = StatusUnhealthy
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
		Latency: time.Duration(latencyMs) * time.Millisecond,
		ResponseIP: originIP, Country: country, City: city,
		CheckedAt: time.Now(),
	}, nil
}

// TestAllProxies concurrently tests all proxies in the pool.
// Inspired by ProfGinx_custom's TestAllProxies().
func (p *Pool) TestAllProxies(ctx context.Context) ([]TestResult, error) {
	p.state.mu.RLock()
	ids := make([]string, len(p.state.proxies))
	for i, px := range p.state.proxies { ids[i] = px.ID }
	p.state.mu.RUnlock()

	results := make([]TestResult, len(ids))
	var wg sync.WaitGroup
	sem := make(chan struct{}, p.state.config.ConcurrentTests)

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
	return results, nil
}

// testProxyDirect performs an actual HTTP test through a proxy.
// Returns: success, origin IP, latency in milliseconds.
func testProxyDirect(px *ProxyInfo) (bool, string, int64) {
	start := time.Now()

	// Build proxy URL
	proxyURLStr := px.buildProxyURL()
	parsed, err := url.Parse(proxyURLStr)
	if err != nil {
		return false, "", 0
	}

	testURL := "https://httpbin.org/ip" // Default test URL

	var client *http.Client

	switch px.Type {
	case ProxyTypeSOCKS4, ProxyTypeSOCKS5, ProxyTypeSOCKS5H:
		// SOCKS proxy requires golang.org/x/net/proxy
		dialer, err := proxy.FromURL(parsed, proxy.Direct)
		if err != nil {
			return false, "", 0
		}
		transport := &http.Transport{Dial: dialer.Dial}
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	default:
		// HTTP/HTTPS proxy
		transport := &http.Transport{Proxy: http.ProxyURL(parsed)}
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}

	resp, err := client.Get(testURL)
	if err != nil {
		return false, "", int64(time.Since(start).Milliseconds())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", int64(time.Since(start).Milliseconds())
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, "", int64(time.Since(start).Milliseconds())
	}

	// Parse response to get exit IP
	var ipResp struct { Origin string `json:"origin"` }
	if json.Unmarshal(body, &ipResp) == nil && ipResp.Origin != "" {
		return true, ipResp.Origin, int64(time.Since(start).Milliseconds())
	}

	return true, strings.TrimSpace(string(body)), int64(time.Since(start).Milliseconds())
}

// lookupGeoIP fetches geographic location for an IP address.
// Inspired by ProfGinx_custom's lookupProxyGeo().
// Returns: country name, city, country code.
func lookupGeoIP(ip string) (string, string, string) {
	// Strip port if present
	if idx := strings.Index(ip, ":"); idx != -1 { ip = ip[:idx] }

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