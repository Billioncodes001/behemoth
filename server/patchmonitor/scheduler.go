package patchmonitor

import (
	"context"
	"log"
	"sync"
	"time"
)

// Start begins the background monitoring loop.
func (m *Monitor) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.stopCh = make(chan struct{})
	stopCh := m.stopCh
	m.mu.Unlock()

	m.wg.Add(1)
	go m.runLoop(context.Background(), stopCh)
	log.Printf("[patchmonitor] Monitor started")
}

// Stop gracefully stops the monitoring loop.
func (m *Monitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()

	m.wg.Wait()
	log.Printf("[patchmonitor] Monitor stopped")
}

// IsRunning returns whether the monitor is currently running.
func (m *Monitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// runLoop is the main monitoring loop.
func (m *Monitor) runLoop(ctx context.Context, stopCh <-chan struct{}) {
	defer m.wg.Done()

	// Perform an immediate full check & launch the Patch Watch AI agent when started.
	m.RunCheckCycle(true)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkDueSources()
		}
	}
}

// checkDueSources finds and checks all sources that are due for a check, and triggers
// the AI Patch Watch agent to analyze discoveries and generate payloads/exploits.
func (m *Monitor) checkDueSources() {
	m.RunCheckCycle(false)
}

// RunCheckCycle checks enabled sources concurrently, auto-generates exploits and
// client-side payloads, and dispatches the Patch Watch AI agent.
func (m *Monitor) RunCheckCycle(forceAll bool) (int, int, int64) {
	sources, err := m.GetEnabledSources()
	if err != nil {
		log.Printf("[patchmonitor] Error getting sources: %v", err)
		return 0, 0, 0
	}

	now := time.Now()
	var due []PatchSource
	for _, src := range sources {
		if !forceAll && src.LastCheck != nil {
			elapsed := now.Sub(*src.LastCheck)
			nextCheck := time.Duration(src.CheckInterval) * time.Second
			if elapsed < nextCheck {
				continue
			}
		}
		due = append(due, src)
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		allAdded []Vulnerability
		sem      = make(chan struct{}, 6)
	)
	for _, src := range due {
		wg.Add(1)
		go func(s PatchSource) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			added := m.checkSource(s)
			if len(added) > 0 {
				mu.Lock()
				allAdded = append(allAdded, added...)
				mu.Unlock()
			}
		}(src)
	}
	wg.Wait()

	checkedCount := len(due)
	m.mu.Lock()
	m.lastScanAt = &now
	cb := m.onAgentWatch
	profID := m.llmProfileID
	m.mu.Unlock()

	var convID int64
	if cb != nil && (checkedCount > 0 || forceAll) {
		convID = cb(profID, allAdded, checkedCount)
		if convID > 0 {
			m.mu.Lock()
			m.lastConversationID = convID
			m.mu.Unlock()
		}
	}
	return checkedCount, len(allAdded), convID
}

