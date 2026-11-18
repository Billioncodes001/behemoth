package patchmonitor

import (
	"context"
	"log"
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

	// Perform an initial check in background when started.
	m.checkDueSources()

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

// checkDueSources finds and checks all sources that are due for a check.
func (m *Monitor) checkDueSources() {
	sources, err := m.GetEnabledSources()
	if err != nil {
		log.Printf("[patchmonitor] Error getting sources: %v", err)
		return
	}

	now := time.Now()
	for _, src := range sources {
		if src.LastCheck != nil {
			elapsed := now.Sub(*src.LastCheck)
			nextCheck := time.Duration(src.CheckInterval) * time.Second
			if elapsed < nextCheck {
				continue
			}
		}
		m.checkSource(src)
	}
}

