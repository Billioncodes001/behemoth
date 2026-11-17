// Package proxyv2 implements an enhanced Proxy Pool system for ARTEX,
// inspired by ProfGinx_custom's anonymity engine.
package proxyv2

import (
	"fmt"
	"sync"
	"time"
)

// ProxyType defines the proxy protocol type.
type ProxyType string

const (
	ProxyTypeHTTP    ProxyType = "http"
	ProxyTypeHTTPS   ProxyType = "https"
	ProxyTypeSOCKS4  ProxyType = "socks4"
	ProxyTypeSOCKS5  ProxyType = "socks5"
	ProxyTypeSOCKS5H ProxyType = "socks5h"
)

// ProxyStatus represents the current health status of a proxy.
type ProxyStatus string

const (
	StatusUntested      ProxyStatus = "untested"
	StatusHealthy       ProxyStatus = "healthy"
	StatusUnhealthy     ProxyStatus = "unhealthy"
	StatusUnhealthyCool ProxyStatus = "unhealthy-cooling"
	StatusInUse         ProxyStatus = "in_use"
	StatusDisabled      ProxyStatus = "disabled"
)

// RotationStrategy defines how proxies are selected.
type RotationStrategy string

const (
	RotationRoundRobin RotationStrategy = "round_robin"
	RotationRandom     RotationStrategy = "random"
	RotationLeastUsed  RotationStrategy = "least_used"
	RotationPerRequest RotationStrategy = "per_request"
)

// ProxyInfo represents a single proxy entry in the pool.
type ProxyInfo struct {
	ID                  string        `json:"id"`
	Type                ProxyType     `json:"type"`
	ProxyTypeAlias      ProxyType     `json:"proxy_type,omitempty"`
	URL                 string        `json:"url,omitempty"`
	Host                string        `json:"host"`
	Port                int           `json:"port"`
	Username            string        `json:"username,omitempty"`
	Password            string        `json:"password,omitempty"`
	Country             string        `json:"country,omitempty"`
	Region              string        `json:"region,omitempty"`
	City                string        `json:"city,omitempty"`
	Status              ProxyStatus   `json:"status"`
	Active              bool          `json:"active"`
	InUse               bool          `json:"in_use"`
	SessionID           string        `json:"session_id,omitempty"`
	LastChecked         time.Time     `json:"last_checked,omitempty"`
	LastCheckedAt       string        `json:"last_checked_at,omitempty"`
	LastUsed            time.Time     `json:"last_used,omitempty"`
	SuccessRate         float64       `json:"success_rate"`
	Latency             time.Duration `json:"latency"`
	LatencyMS           int64         `json:"latency_ms"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	ResponseIP          string        `json:"response_ip,omitempty"`
	Name                string        `json:"name,omitempty"`
	Notes               string        `json:"notes,omitempty"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
	cooldownUntil       time.Time     `json:"-"`
}

// ProxyPoolConfig holds the global proxy pool configuration.
type ProxyPoolConfig struct {
	Enabled                    bool             `json:"enabled"`
	RotationMode               RotationStrategy `json:"rotation_mode"`
	RotationStrategyAlias      RotationStrategy `json:"rotation_strategy,omitempty"`
	RotationInterval           time.Duration    `json:"rotation_interval"`
	RotationIntervalSeconds    int              `json:"rotation_interval_seconds"`
	FailoverEnabled            bool             `json:"failover_enabled"`
	AutoRotateOnFailure        bool             `json:"auto_rotate_on_failure"`
	MaxRetries                 int              `json:"max_retries"`
	MaxConsecutiveFailures     int              `json:"max_consecutive_failures"`
	HealthCheckIntervalSeconds int              `json:"health_check_interval_seconds"`
	CooldownSeconds            int              `json:"cooldown_seconds"`
	SessionSticky              bool             `json:"session_sticky"`
	TestURL                    string           `json:"test_url"`
	TestTimeout                time.Duration    `json:"test_timeout"`
	ConcurrentTests            int              `json:"concurrent_tests"`
}

// DefaultPoolConfig returns sensible defaults.
func DefaultPoolConfig() *ProxyPoolConfig {
	return &ProxyPoolConfig{
		Enabled:                    false,
		RotationMode:               RotationRoundRobin,
		RotationStrategyAlias:      RotationRoundRobin,
		RotationInterval:           30 * time.Second,
		RotationIntervalSeconds:    30,
		FailoverEnabled:            true,
		AutoRotateOnFailure:        true,
		MaxRetries:                 3,
		MaxConsecutiveFailures:     3,
		HealthCheckIntervalSeconds: 30,
		CooldownSeconds:            60,
		SessionSticky:              true,
		TestURL:                    "https://httpbin.org/ip",
		TestTimeout:                10 * time.Second,
		ConcurrentTests:            10,
	}
}

// PoolStats contains aggregate statistics.
type PoolStats struct {
	Total     int `json:"total"`
	Active    int `json:"active"`
	Healthy   int `json:"healthy"`
	Unhealthy int `json:"unhealthy"`
	Untested  int `json:"untested"`
	Unknown   int `json:"unknown"`
	InUse     int `json:"in_use"`
	Disabled  int `json:"disabled"`
	AvgLatency   time.Duration `json:"avg_latency"`
	AvgLatencyMS int64         `json:"avg_latency_ms"`
}

// TestResult represents a single proxy test result.
type TestResult struct {
	ProxyID string `json:"proxy_id"`
	Success bool   `json:"success"`
	Latency time.Duration `json:"latency_ms"`
	ResponseIP string `json:"response_ip,omitempty"`
	Error      string `json:"error,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
	Country    string `json:"country,omitempty"`
	City       string `json:"city,omitempty"`
}

// ImportResult represents bulk import results.
type ImportResult struct {
	Imported int           `json:"imported"`
	Skipped  int           `json:"skipped"`
	Errors   []ImportError `json:"errors,omitempty"`
}

// ImportError represents a parse error.
type ImportError struct {
	Line  int    `json:"line"`
	Input string `json:"input"`
	Error string `json:"error"`
}

// SwitchLog records a proxy switch event.
type SwitchLog struct {
	ID          int       `json:"id"`
	At          time.Time `json:"at"`
	Timestamp   string    `json:"timestamp"`
	From        string    `json:"from"`
	FromProxyID string    `json:"from_proxy_id"`
	To          string    `json:"to"`
	ToProxyID   string    `json:"to_proxy_id"`
	Reason      string    `json:"reason"`
}

// proxyPersist is the serialized form for PostgreSQL.
type proxyPersist struct {
	Config  *ProxyPoolConfig `json:"config"`
	Proxies []ProxyInfo      `json:"proxies"`
	Active  string            `json:"active_id"`
}

// proxyPoolState is the in-memory state.
type proxyPoolState struct {
	mu      sync.RWMutex
	proxies []ProxyInfo
	config  *ProxyPoolConfig
	index   int
	activeID string
	logs    []SwitchLog
}

// BuildProxyURL constructs a full URL string from a ProxyInfo.
func (p *ProxyInfo) BuildProxyURL() string {
	return p.buildProxyURL()
}

// buildProxyURL constructs a URL string from a ProxyInfo.
func (p *ProxyInfo) buildProxyURL() string {
	if p.Username != "" && p.Password != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%d", p.Type, p.Username, p.Password, p.Host, p.Port)
	}
	return fmt.Sprintf("%s://%s:%d", p.Type, p.Host, p.Port)
}

// maskURL returns a masked version for API responses.
func (p *ProxyInfo) maskURL() string {
	if p.Username != "" {
		return fmt.Sprintf("%s://***:***@%s:%d", p.Type, p.Host, p.Port)
	}
	return fmt.Sprintf("%s://%s:%d", p.Type, p.Host, p.Port)
}

// IsAvailable returns whether this proxy can be assigned.
func (p *ProxyInfo) IsAvailable() bool {
	return p.Active && !p.InUse && p.Status != StatusUnhealthy && p.Status != StatusUnhealthyCool
}

// IsUsable returns whether this proxy is functional.
func (p *ProxyInfo) IsUsable() bool {
	return p.Active && p.Status != StatusUnhealthy && p.Status != StatusDisabled
}

