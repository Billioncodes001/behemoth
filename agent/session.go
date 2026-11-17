// Package agent implements host/session tracking for pentest operations.
// Inspired by NukeRat's session management system.
package agent

import (
	"fmt"
	"sync"
	"time"
)

// ---------- Types ----------

// SessionStatus represents the status of a session.
type SessionStatus string

const (
	SessionOnline   SessionStatus = "online"
	SessionOffline  SessionStatus = "offline"
	SessionDead     SessionStatus = "dead"
	SessionActive   SessionStatus = "active"
)

// HostInfo contains information about a target host.
type HostInfo struct {
	Hostname    string            `json:"hostname"`
	IP          string            `json:"ip"`
	OS          string            `json:"os,omitempty"`
	OSVersion   string            `json:"os_version,omitempty"`
	Arch        string            `json:"arch,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	InternalIPs []string          `json:"internal_ips,omitempty"`
	MAC         string            `json:"mac,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Notes       string            `json:"notes,omitempty"`
}

// Session represents an active connection to a target host.
type Session struct {
	ID           int64         `json:"id"`
	HostID       int64         `json:"host_id"`
	Host         *HostInfo     `json:"host"`
	Status       SessionStatus `json:"status"`
	User         string        `json:"user,omitempty"`
	Process      string        `json:"process,omitempty"`
	PID          int           `json:"pid,omitempty"`
	FirstSeen    time.Time     `json:"first_seen"`
	LastSeen     time.Time     `json:"last_seen"`
	TaskID       *int64        `json:"task_id,omitempty"`
	InternalIP   string        `json:"internal_ip,omitempty"`
	NumCommands  int           `json:"num_commands"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// SessionFilter defines filters for session queries.
type SessionFilter struct {
	Status   SessionStatus `json:"status,omitempty"`
	Hostname string        `json:"hostname,omitempty"`
	IP       string        `json:"ip,omitempty"`
	TaskID   *int64        `json:"task_id,omitempty"`
	Limit    int           `json:"limit,omitempty"`
}

// SessionStats contains statistics about sessions.
type SessionStats struct {
	Total       int            `json:"total"`
	Online      int            `json:"online"`
	Offline     int            `json:"offline"`
	Dead        int            `json:"dead"`
	UniqueHosts int            `json:"unique_hosts"`
	ByOS        map[string]int  `json:"by_os"`
}

// ---------- Manager ----------

// Manager manages hosts and sessions.
type Manager struct {
	mu       sync.RWMutex
	hosts    map[int64]*HostInfo
	sessions map[int64]*Session
	nextHostID int64
	nextSessID int64
	config   ManagerConfig
}

// ManagerConfig holds manager configuration.
type ManagerConfig struct {
	MaxHosts    int `json:"max_hosts"`
	MaxSessions int `json:"max_sessions"`
	StaleTimeout time.Duration `json:"stale_timeout"`
}

// NewManager creates a new session manager.
func NewManager(config ManagerConfig) *Manager {
	if config.MaxHosts == 0 { config.MaxHosts = 1000 }
	if config.MaxSessions == 0 { config.MaxSessions = 5000 }
	if config.StaleTimeout == 0 { config.StaleTimeout = 30 * time.Minute }
	return &Manager{
		hosts:     make(map[int64]*HostInfo),
		sessions:  make(map[int64]*Session),
		nextHostID: 1,
		nextSessID: 1,
		config:    config,
	}
}

// RegisterHost registers or updates a host.
func (m *Manager) RegisterHost(host *HostInfo) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if host already exists (by IP)
	for id, h := range m.hosts {
		if h.IP == host.IP {
			// Update existing
			m.hosts[id] = host
			return id
		}
	}

	if len(m.hosts) >= m.config.MaxHosts {
		return 0 // Full
	}

	id := m.nextHostID
	m.nextHostID++
	m.hosts[id] = host
	return id
}

// CreateSession creates a new session for a host.
func (m *Manager) CreateSession(hostID int64, user, process string, taskID *int64) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.sessions) >= m.config.MaxSessions {
		return nil, errMaxSessions
	}

	host, ok := m.hosts[hostID]
	if !ok {
		return nil, errHostNotFound
	}

	now := time.Now()
	sess := &Session{
		ID:        m.nextSessID,
		HostID:    hostID,
		Host:      host,
		Status:    SessionOnline,
		User:      user,
		Process:   process,
		FirstSeen: now,
		LastSeen:  now,
		TaskID:    taskID,
		Metadata:  make(map[string]string),
	}

	m.nextSessID++
	m.sessions[sess.ID] = sess
	return sess, nil
}

// GetSession retrieves a session by ID.
func (m *Manager) GetSession(id int64) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// GetSessions retrieves sessions matching filter.
func (m *Manager) GetSessions(filter SessionFilter) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []*Session
	for _, s := range m.sessions {
		if filter.Status != "" && s.Status != filter.Status { continue }
		if filter.Hostname != "" && s.Host != nil && s.Host.Hostname != filter.Hostname { continue }
		if filter.IP != "" && s.Host != nil && s.Host.IP != filter.IP { continue }

		results = append(results, s)
		if filter.Limit > 0 && len(results) >= filter.Limit { break }
	}
	return results
}

// UpdateSessionHeartbeat updates a session's last seen timestamp.
func (m *Manager) UpdateSessionHeartbeat(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[id]
	if !ok { return errSessionNotFound }
	sess.LastSeen = time.Now()
	sess.NumCommands++
	return nil
}

// SetSessionStatus updates a session's status.
func (m *Manager) SetSessionStatus(id int64, status SessionStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[id]
	if !ok { return errSessionNotFound }
	sess.Status = status
	return nil
}

// CloseSession marks a session as dead.
func (m *Manager) CloseSession(id int64) error { return m.SetSessionStatus(id, SessionDead) }

// CleanupStaleSessions removes sessions that haven't been seen within the timeout.
func (m *Manager) CleanupStaleSessions() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	var cleaned []int64
	now := time.Now()
	for id, s := range m.sessions {
		if now.Sub(s.LastSeen) > m.config.StaleTimeout {
			s.Status = SessionDead
			cleaned = append(cleaned, id)
		}
	}
	return cleaned
}

// Stats returns session statistics.
func (m *Manager) Stats() SessionStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := SessionStats{
		Total: len(m.sessions),
		ByOS:  make(map[string]int),
	}
	hosts := make(map[string]bool)

	for _, s := range m.sessions {
		switch s.Status {
		case SessionOnline: stats.Online++
		case SessionOffline: stats.Offline++
		case SessionDead: stats.Dead++
		}
		if s.Host != nil {
			hosts[s.Host.IP] = true
			if s.Host.OS != "" { stats.ByOS[s.Host.OS]++ }
		}
	}
	stats.UniqueHosts = len(hosts)
	return stats
}

// GetAllHosts returns all registered hosts.
func (m *Manager) GetAllHosts() map[int64]*HostInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[int64]*HostInfo, len(m.hosts))
	for k, v := range m.hosts { result[k] = v }
	return result
}

// ---------- Errors ----------
var (
	errMaxSessions   = fmt.Errorf("session limit reached")
	errHostNotFound  = fmt.Errorf("host not found")
	errSessionNotFound = fmt.Errorf("session not found")
)