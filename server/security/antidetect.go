package security

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// ============================================================
// ANTI-DETECTION & STEALTH MODULE (ProfGinx-inspired)
// Reduces forensically noisy traffic and avoids detection
// ============================================================

// StealthConfig holds stealth configuration
type StealthConfig struct {
	Enabled            bool          `json:"enabled"`
	RequestJitter     time.Duration `json:"request_jitter"`
	UserAgentRotation bool          `json:"ua_rotation"`
	HeaderRandomize   bool          `json:"header_randomize"`
	TLSFingerprinting bool          `json:"tls_fingerprinting"`
	RateLimit         int           `json:"rate_limit_per_min"`
	DelayBetweenReqs  time.Duration `json:"delay_between_requests"`
}

// DefaultStealthConfig returns sensible defaults
func DefaultStealthConfig() StealthConfig {
	return StealthConfig{
		Enabled:            true,
		RequestJitter:     500 * time.Millisecond,
		UserAgentRotation: true,
		HeaderRandomize:   true,
		TLSFingerprinting: true,
		RateLimit:         120,
		DelayBetweenReqs:  500 * time.Millisecond,
	}
}

// AntiDetect provides anti-detection capabilities
type AntiDetect struct {
	config       *StealthConfig
	requestCount map[string]int      // per-IP request counting
	windowStart  map[string]time.Time // rate limit window
	mu           sync.RWMutex
}

// NewAntiDetect creates a new anti-detection module
func NewAntiDetect(cfg StealthConfig) *AntiDetect {
	return &AntiDetect{
		config:       &cfg,
		requestCount: make(map[string]int),
		windowStart:  make(map[string]time.Time),
	}
}

// GetConfig returns a copy of the current stealth configuration.
func (ad *AntiDetect) GetConfig() StealthConfig {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	if ad.config == nil {
		return DefaultStealthConfig()
	}
	return *ad.config
}

// StealthHeaders returns randomized headers for stealthy requests
func (ad *AntiDetect) StealthHeaders(baseUA string) map[string]string {
	if !ad.config.Enabled {
		return map[string]string{
			"User-Agent": baseUA,
		}
	}

	headers := make(map[string]string)

	// User Agent rotation
	if ad.config.UserAgentRotation {
		headers["User-Agent"] = ad.getRandomUA()
	} else {
		headers["User-Agent"] = baseUA
	}

	// Header randomization
	if ad.config.HeaderRandomize {
		headers["Accept"] = ad.randomAccept()
		headers["Accept-Language"] = ad.randomAcceptLang()
		headers["Accept-Encoding"] = "gzip, deflate, br"
		headers["Cache-Control"] = "no-cache"
		headers["Pragma"] = "no-cache"
		headers["Sec-Fetch-Dest"] = "document"
		headers["Sec-Fetch-Mode"] = "navigate"
		headers["Sec-Fetch-Site"] = "none"
		headers["Sec-CH-UA"] = ad.getCHUA()
		headers["Sec-CH-UA-Mobile"] = "?0"
		headers["Sec-CH-UA-Platform"] = ad.getPlatform()
		headers["Upgrade-Insecure-Requests"] = "1"
	}

	return headers
}

// CheckRateLimit checks if IP is within rate limits
func (ad *AntiDetect) CheckRateLimit(ip string) (bool, time.Duration) {
	if !ad.config.Enabled || ad.config.RateLimit <= 0 {
		return true, 0
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	windowStart, exists := ad.windowStart[ip]
	
	// Reset window if expired
	if !exists || now.Sub(windowStart) > time.Minute {
		ad.windowStart[ip] = now
		ad.requestCount[ip] = 1
		return true, 0
	}

	ad.requestCount[ip]++
	if ad.requestCount[ip] > ad.config.RateLimit {
		wait := time.Minute - now.Sub(windowStart)
		return false, wait
	}

	return true, 0
}

// GetJitter returns a random jitter duration
func (ad *AntiDetect) GetJitter() time.Duration {
	if !ad.config.Enabled {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(ad.config.RequestJitter)))
	return time.Duration(n.Int64())
}

// Helper methods for randomization

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
}

func (ad *AntiDetect) getRandomUA() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(userAgents))))
	return userAgents[n.Int64()]
}

var acceptTypes = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

func (ad *AntiDetect) randomAccept() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(acceptTypes))))
	return acceptTypes[n.Int64()]
}

var languages = []string{
	"en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.9,es;q=0.8",
	"en-US,en;q=0.9,fr;q=0.8", "de-DE,de;q=0.9,en;q=0.8", "ja-JA,ja;q=0.9,en;q=0.8",
}

func (ad *AntiDetect) randomAcceptLang() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(languages))))
	return languages[n.Int64()]
}

var chuaValues = []string{
	`"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
	`"Not_A Brand";v="8", "Chromium";v="121", "Google Chrome";v="121"`,
	`"Firefox";v="121.0"`,
	`"Safari";v="17.2"`,
	`"Microsoft Edge";v="120.0.0.0"`,
}

func (ad *AntiDetect) getCHUA() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chuaValues))))
	return chuaValues[n.Int64()]
}

var platforms = []string{"Windows", "macOS", "Linux"}

func (ad *AntiDetect) getPlatform() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(platforms))))
	return fmt.Sprintf(`"%s"`, platforms[n.Int64()])
}