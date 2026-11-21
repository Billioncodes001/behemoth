package proxyv2

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

// Pool is the main proxy pool manager, inspired by ProfGinx_custom's ProxyRotator.
// It handles proxy selection, testing, rotation, and session-sticky assignment.
type Pool struct {
	state  *proxyPoolState
	store  Store // Persistence interface (PostgreSQL)
	onSync func(proxies []ProxyInfo, activeID string, cfg *ProxyPoolConfig)
}

// SetSyncHook registers a callback invoked whenever the pool state is persisted.
func (p *Pool) SetSyncHook(fn func(proxies []ProxyInfo, activeID string, cfg *ProxyPoolConfig)) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	p.onSync = fn
}

// GetRawState returns unmasked proxies, active proxy ID, and config for internal synchronization.
func (p *Pool) GetRawState() ([]ProxyInfo, string, *ProxyPoolConfig) {
	p.state.mu.RLock()
	defer p.state.mu.RUnlock()
	cp := make([]ProxyInfo, len(p.state.proxies))
	copy(cp, p.state.proxies)
	cfg := *p.state.config
	return cp, p.state.activeID, &cfg
}

// SyncFromExternal updates Pool v2 from the legacy/core proxy pool without triggering a feedback loop.
func (p *Pool) SyncFromExternal(proxies []ProxyInfo, activeID string) error {
	p.state.mu.Lock()
	p.state.proxies = proxies
	p.state.activeID = activeID
	var err error
	if p.store != nil {
		err = p.store.SavePool(&proxyPersist{
			Config:  p.state.config,
			Proxies: p.state.proxies,
			Active:  p.state.activeID,
		})
	}
	p.state.mu.Unlock()
	return err
}

// Store defines the persistence interface for the proxy pool.
type Store interface {
	LoadPool() (*proxyPersist, error)
	SavePool(p *proxyPersist) error
}

// NewPool creates a new proxy Pool with the given store.
func NewPool(store Store) *Pool {
	return &Pool{
		state: &proxyPoolState{
			proxies: []ProxyInfo{},
			config:  DefaultPoolConfig(),
			index:   0,
			logs:    []SwitchLog{},
		},
		store: store,
	}
}

// Initialize loads persisted state from the store.
func (p *Pool) Initialize() error {
	persisted, err := p.store.LoadPool()
	if err != nil {
		return fmt.Errorf("load pool: %w", err)
	}
	if persisted != nil {
		p.state.proxies = persisted.Proxies
		p.state.config = persisted.Config
		p.state.activeID = persisted.Active
		if p.state.config == nil {
			p.state.config = DefaultPoolConfig()
		}
	}
	return nil
}

// GetConfig returns a copy of the current pool configuration.
func (p *Pool) GetConfig() *ProxyPoolConfig {
	p.state.mu.RLock()
	defer p.state.mu.RUnlock()
	cfg := *p.state.config
	return &cfg
}

// UpdateConfig updates the pool configuration and persists it.
// Turning Enabled ON selects an initial healthy/active proxy only if none is currently
// selected; turning Enabled OFF clears activeID so no proxy remains marked "In Use".
func (p *Pool) UpdateConfig(cfg *ProxyPoolConfig) error {
	if cfg.RotationStrategyAlias != "" && cfg.RotationMode == "" {
		cfg.RotationMode = cfg.RotationStrategyAlias
	}
	if cfg.RotationMode != "" {
		cfg.RotationStrategyAlias = cfg.RotationMode
	}
	if cfg.RotationIntervalSeconds > 0 {
		cfg.RotationInterval = time.Duration(cfg.RotationIntervalSeconds) * time.Second
	} else if cfg.RotationInterval > 0 {
		cfg.RotationIntervalSeconds = int(cfg.RotationInterval.Seconds())
	}
	if cfg.MaxConsecutiveFailures > 0 && cfg.MaxRetries == 0 {
		cfg.MaxRetries = cfg.MaxConsecutiveFailures
	}
	p.state.mu.Lock()
	p.state.config = cfg
	if !cfg.Enabled {
		p.state.activeID = ""
	} else if p.state.activeID == "" {
		p.state.activeID = p.pickBestHealthyOrActiveLocked()
	}
	defer p.state.mu.Unlock()
	return p.persistLocked()
}

func (p *Pool) pickBestHealthyOrActiveLocked() string {
	var bestHealthyID string
	var bestLat time.Duration
	for _, px := range p.state.proxies {
		if px.Active && px.Status == StatusHealthy {
			if bestHealthyID == "" || (px.Latency > 0 && (bestLat == 0 || px.Latency < bestLat)) {
				bestHealthyID = px.ID
				bestLat = px.Latency
			}
		}
	}
	if bestHealthyID != "" {
		return bestHealthyID
	}
	for _, px := range p.state.proxies {
		if px.Active && px.Status != StatusDisabled && px.Status != StatusUnhealthy {
			return px.ID
		}
	}
	return ""
}

// GetProxies returns all proxies (with masked URLs for API responses).
func (p *Pool) GetProxies() []ProxyInfo {
	p.state.mu.RLock()
	defer p.state.mu.RUnlock()
	result := make([]ProxyInfo, len(p.state.proxies))
	for i, px := range p.state.proxies {
		px := px // copy
		px.ProxyTypeAlias = px.Type
		px.URL = px.maskURL()
		px.LatencyMS = px.Latency.Milliseconds()
		if !px.LastChecked.IsZero() {
			px.LastCheckedAt = px.LastChecked.Format(time.RFC3339)
		}
		result[i] = px
	}
	return result
}

// GetStats returns aggregate pool statistics.
func (p *Pool) GetStats() *PoolStats {
	p.state.mu.RLock()
	defer p.state.mu.RUnlock()
	activeID := ""
	if p.state.config != nil && p.state.config.Enabled {
		activeID = p.state.activeID
	}
	stats := &PoolStats{
		ActiveProxyID: activeID,
	}
	var latSum time.Duration
	var latCount int
	for _, px := range p.state.proxies {
		stats.Total++
		switch px.Status {
		case StatusHealthy:
			stats.Healthy++
		case StatusUnhealthy, StatusUnhealthyCool:
			stats.Unhealthy++
		case StatusUntested, "":
			stats.Untested++
			stats.Unknown++
		case StatusInUse:
			stats.InUse++
		case StatusDisabled:
			stats.Disabled++
		}
		if px.Active {
			stats.Active++
		}
		if px.InUse {
			stats.InUse++
		}
		if px.Latency > 0 && px.Status == StatusHealthy {
			latSum += px.Latency
			latCount++
		}
	}
	if latCount > 0 {
		stats.AvgLatency = latSum / time.Duration(latCount)
	}
	stats.AvgLatencyMS = stats.AvgLatency.Milliseconds()
	return stats
}

// GetLogs returns recent switch logs.
func (p *Pool) GetLogs() []SwitchLog {
	p.state.mu.RLock()
	defer p.state.mu.RUnlock()
	logs := make([]SwitchLog, len(p.state.logs))
	for i, l := range p.state.logs {
		l.ID = i + 1
		if !l.At.IsZero() {
			l.Timestamp = l.At.Format(time.RFC3339)
		}
		l.FromProxyID = l.From
		l.ToProxyID = l.To
		logs[i] = l
	}
	return logs
}

// GetProxyForRequest selects a proxy based on the configured rotation strategy.
// This is the main entry point for HTTP client middleware.
func (p *Pool) GetProxyForRequest(req *http.Request) (*url.URL, error) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()

	if !p.state.config.Enabled || len(p.state.proxies) == 0 {
		return nil, nil // No proxy (direct connection)
	}

	var selected *ProxyInfo
	switch p.state.config.RotationMode {
	case RotationRoundRobin:
		selected = p.selectRoundRobinLocked()
	case RotationRandom:
		selected = p.selectRandomLocked()
	case RotationLeastUsed:
		selected = p.selectLeastUsedLocked()
	case RotationPerRequest:
		selected = p.selectRoundRobinLocked() // Default fallback
	default:
		selected = p.selectRoundRobinLocked()
	}

	if selected == nil {
		return nil, fmt.Errorf("no available proxies in pool")
	}

	// Build proxy URL
	proxyURL, err := url.Parse(selected.buildProxyURL())
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	selected.LastUsed = time.Now()
	return proxyURL, nil
}

// selectRoundRobinLocked selects next proxy in round-robin order.
// Caller must hold p.state.mu Lock (not RLock).
func (p *Pool) selectRoundRobinLocked() *ProxyInfo {
	attempts := len(p.state.proxies)
	for i := 0; i < attempts; i++ {
		idx := p.state.index % len(p.state.proxies)
		p.state.index++
		if p.state.proxies[idx].IsUsable() {
			return &p.state.proxies[idx]
		}
	}
	return nil
}

// selectRandomLocked selects a random available proxy.
func (p *Pool) selectRandomLocked() *ProxyInfo {
	available := []int{}
	for i, px := range p.state.proxies {
		if px.IsUsable() {
			available = append(available, i)
		}
	}
	if len(available) == 0 {
		return nil
	}
	idx := available[rand.Intn(len(available))]
	return &p.state.proxies[idx]
}

// selectLeastUsedLocked selects the least recently used proxy.
func (p *Pool) selectLeastUsedLocked() *ProxyInfo {
	var best *ProxyInfo
	var bestTime time.Time
	for i := range p.state.proxies {
		if !p.state.proxies[i].IsUsable() {
			continue
		}
		if best == nil || p.state.proxies[i].LastUsed.Before(bestTime) {
			best = &p.state.proxies[i]
			bestTime = p.state.proxies[i].LastUsed
		}
	}
	return best
}

// GetProxyForSession returns the proxy assigned to a session (session-sticky).
// Returns nil if session has no proxy assigned.
func (p *Pool) GetProxyForSession(sessionID string) *ProxyInfo {
	p.state.mu.RLock()
	defer p.state.mu.RUnlock()
	for _, px := range p.state.proxies {
		if px.SessionID == sessionID && px.InUse {
			cp := px // copy
			return &cp
		}
	}
	return nil
}

// AssignProxyToSession finds and reserves an available proxy for a session.
// Inspired by ProfGinx_custom's GetAvailableProxy().
func (p *Pool) AssignProxyToSession(sessionID string) (*ProxyInfo, error) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()

	// Check if session already has a proxy
	for i := range p.state.proxies {
		if p.state.proxies[i].SessionID == sessionID && p.state.proxies[i].InUse {
			cp := p.state.proxies[i]
			return &cp, nil
		}
	}

	// Find first available proxy
	for i := range p.state.proxies {
		if p.state.proxies[i].IsAvailable() {
			p.state.proxies[i].InUse = true
			p.state.proxies[i].SessionID = sessionID
			p.state.proxies[i].LastUsed = time.Now()
			p.state.proxies[i].Status = StatusInUse
			p.state.proxies[i].Active = true
			cp := p.state.proxies[i]
			p.persistLocked() // async persist
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("no available proxies (all %d in use or inactive)", len(p.state.proxies))
}

// ReleaseProxy releases a proxy back to the pool (by host:port).
func (p *Pool) ReleaseProxy(host string, port int) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	for i := range p.state.proxies {
		if p.state.proxies[i].Host == host && p.state.proxies[i].Port == port {
			p.state.proxies[i].InUse = false
			p.state.proxies[i].SessionID = ""
			if p.state.proxies[i].Active {
				p.state.proxies[i].Status = StatusHealthy
			}
			p.persistLocked()
			return
		}
	}
}

// ReleaseProxyBySession releases the proxy assigned to a session.
func (p *Pool) ReleaseProxyBySession(sessionID string) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	for i := range p.state.proxies {
		if p.state.proxies[i].SessionID == sessionID {
			p.state.proxies[i].InUse = false
			p.state.proxies[i].SessionID = ""
			if p.state.proxies[i].Active {
				p.state.proxies[i].Status = StatusHealthy
			}
			p.persistLocked()
			return
		}
	}
}

func (p *Pool) appendProxyNoPersistLocked(px ProxyInfo) {
	if px.ID == "" {
		px.ID = fmt.Sprintf("px-%d-%d", time.Now().UnixNano(), len(p.state.proxies))
	}
	if px.Status == "" {
		px.Status = StatusUntested
	}
	if px.Status != StatusDisabled {
		px.Active = true
	}
	now := time.Now()
	if px.CreatedAt.IsZero() {
		px.CreatedAt = now
	}
	px.UpdatedAt = now
	p.state.proxies = append(p.state.proxies, px)
}

// AddProxy adds a new proxy to the pool.
func (p *Pool) AddProxy(px ProxyInfo) error {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	p.appendProxyNoPersistLocked(px)
	return p.persistLocked()
}

// ClearAllProxies removes all proxies from the pool.
func (p *Pool) ClearAllProxies() (int, error) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	n := len(p.state.proxies)
	p.state.proxies = []ProxyInfo{}
	p.state.activeID = ""
	return n, p.persistLocked()
}

// ActivateProxy enables the pool, marks id active, and selects it as the active egress proxy.
func (p *Pool) ActivateProxy(id string) error {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	found := false
	for i := range p.state.proxies {
		if p.state.proxies[i].ID == id {
			p.state.proxies[i].Active = true
			if p.state.proxies[i].Status == StatusDisabled {
				if p.state.proxies[i].ResponseIP != "" {
					p.state.proxies[i].Status = StatusHealthy
				} else {
					p.state.proxies[i].Status = StatusUntested
				}
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("proxy not found: %s", id)
	}
	oldID := p.state.activeID
	p.state.activeID = id
	p.state.config.Enabled = true
	if oldID != id {
		p.state.logs = append(p.state.logs, SwitchLog{
			At: time.Now(), From: oldID, To: id, Reason: "manual_activate",
		})
		if len(p.state.logs) > 100 {
			p.state.logs = p.state.logs[len(p.state.logs)-100:]
		}
	}
	return p.persistLocked()
}

// RemoveProxy removes a proxy by ID.
func (p *Pool) RemoveProxy(id string) error {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	for i, px := range p.state.proxies {
		if px.ID == id {
			p.state.proxies = append(p.state.proxies[:i], p.state.proxies[i+1:]...)
			return p.persistLocked()
		}
	}
	return fmt.Errorf("proxy not found: %s", id)
}

// UpdateProxy updates an existing proxy's properties.
func (p *Pool) UpdateProxy(id string, updates map[string]interface{}) error {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	for i := range p.state.proxies {
		if p.state.proxies[i].ID == id {
			if v, ok := updates["name"]; ok {
				p.state.proxies[i].Name = v.(string)
			}
			if v, ok := updates["notes"]; ok {
				p.state.proxies[i].Notes = v.(string)
			}
			if v, ok := updates["active"]; ok {
				p.state.proxies[i].Active = v.(bool)
			}
			if v, ok := updates["username"]; ok {
				p.state.proxies[i].Username = v.(string)
			}
			if v, ok := updates["password"]; ok {
				p.state.proxies[i].Password = v.(string)
			}
			p.state.proxies[i].UpdatedAt = time.Now()
			return p.persistLocked()
		}
	}
	return fmt.Errorf("proxy not found: %s", id)
}

// ClearFailedProxies removes all proxies with failed/unhealthy status.
// Inspired by ProfGinx_custom's ClearFailedProxies().
func (p *Pool) ClearFailedProxies() (int, error) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	kept := []ProxyInfo{}
	removed := 0
	for _, px := range p.state.proxies {
		if px.Active && px.Status != StatusUnhealthy && px.Status != StatusDisabled {
			kept = append(kept, px)
		} else if !px.InUse {
			removed++
		} else {
			kept = append(kept, px)
		}
	}
	p.state.proxies = kept
	return removed, p.persistLocked()
}

// DeactivateProxy stops using a proxy as the active egress without marking it disabled,
// so no other proxy in the table is automatically put "In Use".
func (p *Pool) DeactivateProxy(id string) error {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if id == "" || p.state.activeID == id {
		p.state.activeID = ""
		p.state.config.Enabled = false
	}
	return p.persistLocked()
}

// ToggleProxyActive enables/disables a single proxy by ID in the Web UI.
// IMPORTANT: Disabling the currently "In Use" proxy clears activeID and disables pool
// routing instead of automatically putting the next row in the table "In Use".
func (p *Pool) ToggleProxyActive(id string) error {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	for i := range p.state.proxies {
		if p.state.proxies[i].ID == id {
			p.state.proxies[i].Active = !p.state.proxies[i].Active
			if !p.state.proxies[i].Active {
				p.state.proxies[i].Status = StatusDisabled
				p.state.proxies[i].InUse = false
				if p.state.activeID == id {
					p.state.activeID = ""
					p.state.config.Enabled = false
				}
			} else if p.state.proxies[i].Status == StatusDisabled {
				if p.state.proxies[i].ResponseIP != "" {
					p.state.proxies[i].Status = StatusHealthy
				} else {
					p.state.proxies[i].Status = StatusUntested
				}
			}
			return p.persistLocked()
		}
	}
	return fmt.Errorf("proxy not found: %s", id)
}

// SetProxyActive explicitly enables or disables a single proxy by ID.
// When autoFailover is true (used by AI agents quarantining a failing proxy mid-scan)
// and the pool is enabled, disabling the active proxy fails over to another healthy proxy;
// when autoFailover is false (manual UI action), it never auto-promotes another row.
func (p *Pool) SetProxyActive(id string, active bool, autoFailover ...bool) error {
	failover := len(autoFailover) > 0 && autoFailover[0]
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	for i := range p.state.proxies {
		if p.state.proxies[i].ID == id {
			p.state.proxies[i].Active = active
			if !active {
				p.state.proxies[i].Status = StatusDisabled
				p.state.proxies[i].InUse = false
				if p.state.activeID == id {
					if failover && p.state.config != nil && p.state.config.Enabled {
						p.state.activeID = p.pickBestHealthyOrActiveLocked()
						if p.state.activeID == "" {
							p.state.config.Enabled = false
						}
					} else {
						p.state.activeID = ""
						p.state.config.Enabled = false
					}
				}
			} else if p.state.proxies[i].Status == StatusDisabled {
				if p.state.proxies[i].ResponseIP != "" {
					p.state.proxies[i].Status = StatusHealthy
				} else {
					p.state.proxies[i].Status = StatusUntested
				}
			}
			return p.persistLocked()
		}
	}
	return fmt.Errorf("proxy not found: %s", id)
}

// ForceRotate forces rotation to next proxy.
func (p *Pool) ForceRotate(reason string) (*ProxyInfo, error) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if len(p.state.proxies) == 0 {
		return nil, fmt.Errorf("no proxies in pool")
	}
	oldID := p.state.activeID
	selected := p.selectRoundRobinLocked()
	if selected == nil {
		return nil, fmt.Errorf("no available proxies")
	}
	p.state.activeID = selected.ID
	p.state.logs = append(p.state.logs, SwitchLog{
		At: time.Now(), From: oldID, To: selected.ID, Reason: reason,
	})
	if len(p.state.logs) > 100 {
		p.state.logs = p.state.logs[len(p.state.logs)-100:]
	}
	cp := *selected
	return &cp, p.persistLocked()
}

// persistLocked saves state. Caller must hold mutex.
// IMPORTANT: Never auto-select a replacement activeID here when activeID is empty or
// disabled — otherwise clicking "Disable" or importing proxies unexpectedly forces
// the next proxy row into "In Use". Replacement selection happens ONLY when explicitly
// enabling the pool (UpdateConfig), clicking "Use" (ActivateProxy), or rotating (ForceRotate).
func (p *Pool) persistLocked() error {
	if p.state.activeID != "" {
		valid := false
		for _, px := range p.state.proxies {
			if px.ID == p.state.activeID && px.Active && px.Status != StatusDisabled {
				valid = true
				break
			}
		}
		if !valid {
			p.state.activeID = ""
		}
	}
	if p.state.config != nil && !p.state.config.Enabled {
		p.state.activeID = ""
	}
	var err error
	if p.store != nil {
		persisted := &proxyPersist{Config: p.state.config, Proxies: p.state.proxies, Active: p.state.activeID}
		err = p.store.SavePool(persisted)
	}
	if p.onSync != nil {
		cp := make([]ProxyInfo, len(p.state.proxies))
		copy(cp, p.state.proxies)
		activeID := p.state.activeID
		cfg := *p.state.config
		fn := p.onSync
		go fn(cp, activeID, &cfg)
	}
	return err
}
