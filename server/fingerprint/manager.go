// Package fingerprint provides dynamic fingerprint generation for ARTEX.
// All external communications use randomized identifiers to prevent
// tool detection via static signatures (User-Agents, headers, cookies, etc.)
//
// Key design principles:
//   - No static strings that identify the tool
//   - Per-session or per-request randomization
//   - Realistic values drawn from actual browser/tool fingerprints
//   - Configurable rotation strategies
package fingerprint

import (
	"fmt"
	"sync"
	"time"
)

// Manager handles all dynamic fingerprint generation.
type Manager struct {
	mu             sync.RWMutex
	sessionFPs     map[string]*SessionFingerprint // session ID → fingerprint
	cookieSuffix   string                         // randomized at startup
	headerSuffix   string                         // randomized at startup
	uaPool         []string                       // User-Agent rotation pool
	currentUAIndex int
}

// SessionFingerprint holds all dynamic identifiers for a single session.
type SessionFingerprint struct {
	SessionID    string
	UserAgent    string
	CookieName   string
	AuthHeader   string // replaces static "X-Artex-Auth"
	RequestID    string // correlation ID for request tracing
	CreatedAt    time.Time
	RotatedAt    time.Time
	ExtraHeaders map[string]string // additional randomized headers
}

// Global singleton instance
var (
	globalManager *Manager
	once          sync.Once
)

// Initialize creates and returns the global fingerprint manager.
// Call once at application startup.
func Initialize() *Manager {
	once.Do(func() {
		suffix := generateRandomString(8)
		globalManager = &Manager{
			sessionFPs:     make(map[string]*SessionFingerprint),
			cookieSuffix:   suffix,
			headerSuffix:   suffix,
			uaPool:         getDefaultUAPool(),
			currentUAIndex: 0,
		}
	})
	return globalManager
}

// GetManager returns the global fingerprint manager.
func GetManager() *Manager {
	if globalManager == nil {
		return Initialize()
	}
	return globalManager
}

// GetOrCreateSessionFP returns the fingerprint for a session, creating one if needed.
func (m *Manager) GetOrCreateSessionFP(sessionID string) *SessionFingerprint {
	m.mu.RLock()
	if fp, ok := m.sessionFPs[sessionID]; ok {
		m.mu.RUnlock()
		return fp
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	// Double-check after acquiring write lock
	if fp, ok := m.sessionFPs[sessionID]; ok {
		return fp
	}

	fp := &SessionFingerprint{
		SessionID:    sessionID,
		UserAgent:    m.getRandomUA(),
		CookieName:   fmt.Sprintf("sid_%s_%s", m.cookieSuffix, generateRandomString(12)),
		AuthHeader:   fmt.Sprintf("X-Auth-%s", m.headerSuffix),
		RequestID:    generateRequestID(),
		CreatedAt:    time.Now(),
		RotatedAt:    time.Now(),
		ExtraHeaders: m.generateExtraHeaders(),
	}
	m.sessionFPs[sessionID] = fp
	return fp
}

// RotateSessionFP forces rotation of a session's fingerprints.
func (m *Manager) RotateSessionFP(sessionID string) *SessionFingerprint {
	m.mu.Lock()
	defer m.mu.Unlock()

	fp := &SessionFingerprint{
		SessionID:    sessionID,
		UserAgent:    m.getRandomUA(),
		CookieName:   fmt.Sprintf("sid_%s_%s", m.cookieSuffix, generateRandomString(12)),
		AuthHeader:   fmt.Sprintf("X-Auth-%s", generateRandomString(8)),
		RequestID:    generateRequestID(),
		CreatedAt:    time.Now(),
		RotatedAt:    time.Now(),
		ExtraHeaders: m.generateExtraHeaders(),
	}
	m.sessionFPs[sessionID] = fp
	return fp
}

// RemoveSessionFP removes a session's fingerprint (cleanup on logout).
func (m *Manager) RemoveSessionFP(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessionFPs, sessionID)
}

// getRandomUA returns a random User-Agent from the pool.
func (m *Manager) getRandomUA() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.uaPool) == 0 {
		return getDefaultUAPool()[0]
	}
	ua := m.uaPool[m.currentUAIndex%len(m.uaPool)]
	m.currentUAIndex++
	return ua
}

// generateExtraHeaders creates randomized extra headers to mimic real browsers.
func (m *Manager) generateExtraHeaders() map[string]string {
	return map[string]string{
		fmt.Sprintf("X-Request-%s", generateRandomString(6)): generateRequestID(),
		fmt.Sprintf("X-ID-%s", generateRandomString(4)):      generateRandomString(16),
	}
}

// GetDynamicCookieName returns the dynamic cookie name for basic auth.
// Replaces static "artex_basic_auth".
func GetDynamicCookieName() string {
	m := GetManager()
	return fmt.Sprintf("auth_%s", m.cookieSuffix)
}

// GetDynamicAuthHeaderName returns the dynamic auth header name.
// Replaces static "X-Artex-Auth".
func GetDynamicAuthHeaderName() string {
	m := GetManager()
	return fmt.Sprintf("X-Auth-%s", m.headerSuffix)
}
