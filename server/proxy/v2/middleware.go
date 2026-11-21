package proxyv2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Middleware provides HTTP client middleware for automatic proxy rotation.
// Integrates the proxy pool with Go's http.Client for transparent proxy usage.
type Middleware struct {
	pool       *Pool
	httpClient *http.Client
	transport  *http.Transport
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

// CloseIdleConnections closes any idle keep-alive connections in the shared transport.
func (m *Middleware) CloseIdleConnections() {
	m.mu.RLock()
	tr := m.transport
	m.mu.RUnlock()
	if tr != nil {
		tr.CloseIdleConnections()
	}
}

// GetHTTPClient returns an *http.Client that automatically routes through
// the proxy pool. Both the client and its underlying connection-pooled
// *http.Transport are reused across calls (thread-safe, zero socket leaks).
func (m *Middleware) GetHTTPClient() *http.Client {
	m.mu.RLock()
	if m.httpClient != nil {
		client := m.httpClient
		m.mu.RUnlock()
		return client
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.httpClient != nil {
		return m.httpClient
	}

	m.transport = &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			if !m.IsEnabled() || m.pool == nil {
				return nil, nil
			}
			proxyURL, err := m.pool.GetProxyForRequest(req)
			if err != nil {
				// No proxy available or pool disabled — fall back to direct connection.
				return nil, nil
			}
			return proxyURL, nil
		},
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
	m.httpClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: m.transport,
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
func (m *Middleware) Get(urlStr string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	return m.Do(req)
}

// Post performs a POST request through the proxy pool, serializing body as needed.
func (m *Middleware) Post(urlStr string, contentType string, body interface{}) (*http.Response, error) {
	var reader io.Reader
	switch v := body.(type) {
	case nil:
		reader = nil
	case io.Reader:
		reader = v
	case []byte:
		reader = bytes.NewReader(v)
	case string:
		reader = strings.NewReader(v)
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal POST body: %w", err)
		}
		reader = bytes.NewReader(encoded)
		if contentType == "" {
			contentType = "application/json"
		}
	}
	req, err := http.NewRequest(http.MethodPost, urlStr, reader)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return m.Do(req)
}
