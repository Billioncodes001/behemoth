// Package llmhttp contains the shared outbound HTTP client construction used by
// LLM endpoints. An empty proxy deliberately means direct and does not inherit
// HTTP_PROXY/HTTPS_PROXY from the process environment.
package llmhttp

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NewClient builds an HTTP client for an LLM endpoint with high-concurrency
// HTTP/2 & TLS keep-alive pooling so parallel Planner/Worker/Chat/Judge calls
// reuse warm connections instead of repeating TCP+TLS handshakes.
func NewClient(rawProxy string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 128
	transport.MaxIdleConnsPerHost = 32
	transport.IdleConnTimeout = 120 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ForceAttemptHTTP2 = true
	rawProxy = strings.TrimSpace(rawProxy)
	if rawProxy == "" {
		transport.Proxy = nil
	} else {
		proxyURL, err := url.Parse(rawProxy)
		if err != nil {
			return nil, fmt.Errorf("llm: invalid proxy %q: %w", rawProxy, err)
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5":
			transport.Proxy = http.ProxyURL(proxyURL)
		case "":
			return nil, fmt.Errorf("llm: proxy %q missing scheme (use http://, https:// or socks5://)", rawProxy)
		default:
			return nil, fmt.Errorf("llm: unsupported proxy scheme %q (use http, https or socks5)", proxyURL.Scheme)
		}
	}
	return &http.Client{Transport: transport}, nil
}
