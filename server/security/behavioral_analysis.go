package security

import (
	"sync"
	"time"
)

// ============================================================
// BEHAVIORAL ANALYSIS MODULE (ProfGinx-inspired)
// Detects bots by analyzing user behavior patterns
// ============================================================

// BehaviorConfig holds behavioral analysis configuration
type BehaviorConfig struct {
	Enabled          bool          `json:"enabled"`
	SessionTimeout   time.Duration `json:"session_timeout"`
	MinSessionLength time.Duration `json:"min_session_length"`
	MaxClickRate     int           `json:"max_click_rate_per_sec"` // max clicks per second
	MaxKeyRate       int           `json:"max_key_rate_per_sec"`   // max keystrokes per second
	SuspiciousScore  int           `json:"suspicious_threshold"`
}

// DefaultBehaviorConfig returns sensible defaults
func DefaultBehaviorConfig() BehaviorConfig {
	return BehaviorConfig{
		Enabled:          true,
		SessionTimeout:   30 * time.Minute,
		MinSessionLength: 5 * time.Second,
		MaxClickRate:     15, // 15 clicks/sec is suspicious
		MaxKeyRate:       30, // 30 keystrokes/sec is suspicious
		SuspiciousScore:  70,
	}
}

// SessionBehavior tracks behavior within a session
type SessionBehavior struct {
	SessionID      string
	StartTime      time.Time
	LastActivity   time.Time
	ClickCount     int
	KeyCount       int
	ScrollCount    int
	MouseMovements int
	ClickTimes     []time.Time
	KeyTimes       []time.Time
	ScrollDepths   []int
	PageViews      []string
	mu             sync.Mutex
}

// BehavioralAnalyzer analyzes user behavior for bot detection
type BehavioralAnalyzer struct {
	config   *BehaviorConfig
	sessions map[string]*SessionBehavior
	mu       sync.RWMutex
}

// NewBehavioralAnalyzer creates a new behavioral analyzer
func NewBehavioralAnalyzer(cfg BehaviorConfig) *BehavioralAnalyzer {
	if !cfg.Enabled {
		cfg = BehaviorConfig{Enabled: false}
	}
	return &BehavioralAnalyzer{
		config:   &cfg,
		sessions: make(map[string]*SessionBehavior),
	}
}

// CreateSession creates a new behavior tracking session
func (ba *BehavioralAnalyzer) CreateSession(sessionID string) *SessionBehavior {
	if !ba.config.Enabled {
		return nil
	}
	ba.mu.Lock()
	defer ba.mu.Unlock()

	sess := &SessionBehavior{
		SessionID:    sessionID,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		ClickTimes:   []time.Time{},
		KeyTimes:     []time.Time{},
		ScrollDepths: []int{},
		PageViews:    []string{},
	}
	ba.sessions[sessionID] = sess
	return sess
}

// RecordClick records a click event
func (ba *BehavioralAnalyzer) RecordClick(sessionID string) {
	if !ba.config.Enabled {
		return
	}
	ba.mu.RLock()
	sess, ok := ba.sessions[sessionID]
	ba.mu.RUnlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.ClickCount++
	sess.ClickTimes = append(sess.ClickTimes, time.Now())
	sess.LastActivity = time.Now()
}

// RecordKeystroke records a keystroke event
func (ba *BehavioralAnalyzer) RecordKeystroke(sessionID string) {
	if !ba.config.Enabled {
		return
	}
	ba.mu.RLock()
	sess, ok := ba.sessions[sessionID]
	ba.mu.RUnlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.KeyCount++
	sess.KeyTimes = append(sess.KeyTimes, time.Now())
	sess.LastActivity = time.Now()
}

// RecordScroll records a scroll event
func (ba *BehavioralAnalyzer) RecordScroll(sessionID string, depth int) {
	if !ba.config.Enabled {
		return
	}
	ba.mu.RLock()
	sess, ok := ba.sessions[sessionID]
	ba.mu.RUnlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.ScrollCount++
	sess.ScrollDepths = append(sess.ScrollDepths, depth)
	sess.LastActivity = time.Now()
}

// RecordPageView records a page view event
func (ba *BehavioralAnalyzer) RecordPageView(sessionID string, page string) {
	if !ba.config.Enabled {
		return
	}
	ba.mu.RLock()
	sess, ok := ba.sessions[sessionID]
	ba.mu.RUnlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.PageViews = append(sess.PageViews, page)
	sess.LastActivity = time.Now()
}

// BehaviorAnalysisResult represents the result of behavior analysis
type BehaviorAnalysisResult struct {
	IsBot           bool     `json:"is_bot"`
	Score           int      `json:"score"`
	Confidence      float64  `json:"confidence"`
	Flags           []string `json:"flags"`
	Reasons         []string `json:"reasons"`
	SessionDuration string   `json:"session_duration"`
	ClickRate       float64  `json:"click_rate"`
	KeyRate         float64  `json:"key_rate"`
}

// Analyze analyzes session behavior and returns bot detection result
func (ba *BehavioralAnalyzer) Analyze(sessionID string) *BehaviorAnalysisResult {
	result := &BehaviorAnalysisResult{
		IsBot:      false,
		Score:      0,
		Confidence: 0,
		Flags:      []string{},
		Reasons:    []string{},
	}

	if !ba.config.Enabled {
		return result
	}

	ba.mu.RLock()
	sess, ok := ba.sessions[sessionID]
	ba.mu.RUnlock()
	if !ok {
		return result
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	// Calculate session duration
	duration := sess.LastActivity.Sub(sess.StartTime)
	result.SessionDuration = duration.String()

	// Check minimum session length (bots often have very short sessions)
	if duration < ba.config.MinSessionLength && sess.ClickCount > 10 {
		result.Score += 30
		result.Flags = append(result.Flags, "SHORT_SESSION_HIGH_ACTIVITY")
		result.Reasons = append(result.Reasons, "Very short session with high activity")
	}

	// Calculate click rate (clicks per second)
	if len(sess.ClickTimes) > 1 && duration.Seconds() > 0 {
		clickRate := float64(sess.ClickCount) / duration.Seconds()
		result.ClickRate = clickRate
		if clickRate > float64(ba.config.MaxClickRate) {
			result.Score += 25
			result.Flags = append(result.Flags, "HIGH_CLICK_RATE")
			result.Reasons = append(result.Reasons, "Unnatural click rate detected")
		}
	}

	// Calculate keystroke rate (keystrokes per second)
	if len(sess.KeyTimes) > 1 && duration.Seconds() > 0 {
		keyRate := float64(sess.KeyCount) / duration.Seconds()
		result.KeyRate = keyRate
		if keyRate > float64(ba.config.MaxKeyRate) {
			result.Score += 25
			result.Flags = append(result.Flags, "HIGH_KEY_RATE")
			result.Reasons = append(result.Reasons, "Unnatural typing speed detected")
		}
	}

	// Check for lack of scrolling (real users usually scroll)
	if sess.ScrollCount == 0 && sess.ClickCount > 5 && len(sess.PageViews) > 1 {
		result.Score += 15
		result.Flags = append(result.Flags, "NO_SCROLLING")
		result.Reasons = append(result.Reasons, "Multiple page views but no scrolling")
	}

	// Check for linear click timing (bots have very regular intervals)
	if ba.hasLinearTiming(sess.ClickTimes) {
		result.Score += 20
		result.Flags = append(result.Flags, "LINEAR_CLICK_TIMING")
		result.Reasons = append(result.Reasons, "Clicks have suspiciously regular timing")
	}

	// Determine if bot based on score
	result.IsBot = result.Score >= ba.config.SuspiciousScore
	result.Confidence = float64(result.Score) / float64(ba.config.SuspiciousScore)
	if result.Confidence > 1.0 {
		result.Confidence = 1.0
	}

	return result
}

// hasLinearTiming checks if events have suspiciously regular timing (bot-like)
func (ba *BehavioralAnalyzer) hasLinearTiming(times []time.Time) bool {
	if len(times) < 5 {
		return false
	}
	// Calculate variance in intervals
	var intervals []time.Duration
	for i := 1; i < len(times); i++ {
		intervals = append(intervals, times[i].Sub(times[i-1]))
	}
	// Calculate mean interval
	var total time.Duration
	for _, iv := range intervals {
		total += iv
	}
	mean := time.Duration(int64(total) / int64(len(intervals)))

	// Check if most intervals are very close to mean (low variance)
	var closeCount int
	for _, iv := range intervals {
		diff := iv - mean
		if diff < 0 {
			diff = -diff
		}
		if diff < 50*time.Millisecond { // within 50ms of mean
			closeCount++
		}
	}
	// If >80% of intervals are very regular, it's suspicious
	return float64(closeCount)/float64(len(intervals)) > 0.8
}
