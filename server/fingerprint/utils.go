package fingerprint

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// generateRandomString creates a random alphanumeric string of given length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

// generateRequestID creates a unique request ID for correlation.
func generateRequestID() string {
	ts := fmt.Sprintf("%08x", time.Now().UnixNano()%100000000)
	randPart := generateRandomString(12)
	return ts + randPart
}

// GetRandomUA returns a random User-Agent for one-off use (not session-bound).
func GetRandomUA() string {
	m := GetManager()
	return m.getRandomUA()
}

// GetSessionFP returns or creates a session fingerprint.
// For use with authenticated sessions that need stable-but-dynamic identity.
func GetSessionFP(sessionID string) *SessionFingerprint {
	m := GetManager()
	return m.GetOrCreateSessionFP(sessionID)
}

// RotateSessionFP forces rotation of a session's fingerprints at runtime.
// Call this periodically or on security events.
func RotateSessionFP(sessionID string) *SessionFingerprint {
	m := GetManager()
	return m.RotateSessionFP(sessionID)
}

// === RUNTIME ROTATION SUPPORT ===

// RotatingTransport wraps http.RoundTripper with dynamic fingerprints per request.
type RotatingTransport struct {
	Base http.RoundTripper
}

// RoundTrip executes a single HTTP transaction with dynamic fingerprints.
func (t *RotatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Set dynamic User-Agent for each request
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", GetRandomUA())
	}

	// Add dynamic correlation header
	req.Header.Set(
		fmt.Sprintf("X-Req-%s", generateRandomString(4)),
		generateRequestID(),
	)

	return t.Base.RoundTrip(req)
}

// NewRotatingClient creates an *http.Client with dynamic fingerprint rotation.
// Use this for all outbound HTTP requests that need anonymity.
func NewRotatingClient(baseClient *http.Client) *http.Client {
	if baseClient == nil {
		baseClient = &http.Client{Timeout: 30 * time.Second}
	}

	var baseTransport http.RoundTripper
	if baseClient.Transport != nil {
		baseTransport = baseClient.Transport
	} else {
		baseTransport = &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		}
	}

	client := *baseClient // copy
	client.Transport = &RotatingTransport{Base: baseTransport}
	return &client
}

// === TIMED ROTATION GOROUTINE ===

// StartRotationScheduler begins a background goroutine that rotates fingerprints
// at the given interval. Call this at startup for continuous rotation.
func StartRotationScheduler(interval time.Duration) <-chan struct{} {
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Rotate all session FPs
				m := GetManager()
				m.mu.Lock()
				for sessionID := range m.sessionFPs {
					// Create new FP for each session (lazy rotation on next use)
					fp := m.sessionFPs[sessionID]
					fp.UserAgent = m.getRandomUA()
					fp.RequestID = generateRequestID()
					fp.RotatedAt = time.Now()
					m.sessionFPs[sessionID] = fp
				}
				// Also rotate the global suffixes periodically (optional - more aggressive)
				// m.cookieSuffix = generateRandomString(8)
				// m.headerSuffix = generateRandomString(8)
				m.mu.Unlock()
			case <-stopCh:
				return
			}
		}
	}()
	return stopCh
}
