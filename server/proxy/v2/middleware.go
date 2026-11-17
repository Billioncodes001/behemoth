package proxyv2

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)
// Middleware provides HTTP client middleware for automatic proxy rotation.
// Integrates the proxy pool with Go's http.Client for transparent proxy usage.
type Middleware struct {
	pool       *Pool
	httpClient *http.Client
	mu         sync.RWMutex
	enabled    bool
}

// NewMiddleware creates a new proxy middleware backed by the given pool.
func NewMiddleware(pool *Pool) *Middleware {
	return &Middleware{
		pool:    pool,
		enabled: true,
	}
}

// SetEnabled enables or disables the proxy middleware.
// When disabled, requests go direct (no proxy).
func (m *Middleware) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// IsEnabled returns whether the middleware is currently enabled.
func (m *Middleware) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// GetHTTPClient returns an *http.Client that automatically routes through
// the proxy pool. The client is reused across calls (thread-safe).
func (m *Middleware) GetHTTPClient() *http.Client {
	m.mu.RLock()
	if m.httpClient != nil {
		client := m.httpClient
		m.mu.RUnlock()
		return client
	}
	m.mu.RUnlock()

	// Create client on first use
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.httpClient != nil {
		return m.httpClient
	}

	m.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &proxyTransport{middleware: m},
	}
	return m.httpClient
}

// Do executes an HTTP request through the proxy pool.
// Automatically selects a proxy based on the pool's rotation strategy.
func (m *Middleware) Do(req *http.Request) (*http.Response, error) {
	if !m.IsEnabled() {
		return http.DefaultClient.Do(req)
	}
	client := m.GetHTTPClient()
	return client.Do(req)
}

// Get performs a GET request through the proxy pool.
func (m *Middleware) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return m.Do(req)
}

// Post performs a POST request through the proxy pool.
func (m *Middleware) Post(url string, contentType string, body interface{}) (*http.Response, error) {
	// TODO: Implement POST with body serialization
	return nil, fmt.Errorf("not yet implemented")
}

// === INTERNAL TRANSPORT ===

// proxyTransport implements http.RoundTripper with automatic proxy selection.
type proxyTransport struct {
	middleware *Middleware
}

// RoundTrip executes a single HTTP transaction using a proxy from the pool.
func (t *proxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get proxy URL from pool
	proxyURL, err := t.middleware.pool.GetProxyForRequest(req)
	if err != nil {
		// No proxy available or pool disabled - go direct
		transport := &http.Transport{}
		return transport.RoundTrip(req)
	}
	if proxyURL == nil {
		// Pool enabled but returning nil means direct connection
		transport := &http.Transport{}
		return transport.RoundTrip(req)
	}

	// Create transport with proxy
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}

	return transport.RoundTrip(req)
}