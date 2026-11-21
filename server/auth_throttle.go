package server

import (
	"sync"
	"time"
)

// Login brute-force protection.
//
// /api/auth/* is exempt from securityMiddleware (auth.go's requireAuth also lets
// it through so an unauthenticated visitor can log in), which means the generic
// antiDetect rate limiter never sees a login attempt. Without this guard the only
// cost of guessing the admin password is one bcrypt compare per request — cheap
// enough to brute force anonymously.
//
// The policy is failure-based rather than request-based so normal use (a browser
// retry, a page reload) never trips it: the first failures inside the window are
// free, and only the ones past the allowance start a lockout that doubles per
// extra failure up to a cap. A successful login clears the entry.
const (
	loginMaxFailures  = 5                // failures allowed inside the window
	loginFailureTTL   = 15 * time.Minute // failures older than this no longer count
	loginLockoutStep  = 15 * time.Second // first lockout; doubles per extra failure
	loginMaxLockout   = 15 * time.Minute // lockout cap
	loginMaxTrackedIP = 10_000           // bound on the map; prune past this
)

// loginFailures tracks the failure history of one client IP.
type loginFailures struct {
	count       int
	lastFailure time.Time
	lockedUntil time.Time
}

// loginGuard is an in-memory, per-IP failure limiter. It deliberately does not
// persist: a restart clearing every lockout is an acceptable trade for not
// paying a DB round-trip on each login, and the state only ever delays an
// attacker (the password hash is still the real barrier).
type loginGuard struct {
	mu      sync.Mutex
	entries map[string]loginFailures
}

// retryAfter reports how much longer ip must wait, or 0 when it may try now.
// Expired lockouts are cleared so the count starts over.
func (g *loginGuard) retryAfter(ip string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.entries[ip]
	if !ok {
		return 0
	}
	now := time.Now()
	if e.lockedUntil.After(now) {
		return e.lockedUntil.Sub(now)
	}
	if e.lastFailure.IsZero() || now.Sub(e.lastFailure) > loginFailureTTL {
		delete(g.entries, ip)
	}
	return 0
}

// fail records one wrong password for ip and returns the resulting lockout
// duration (0 while still inside the allowance).
func (g *loginGuard) fail(ip string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.entries == nil {
		g.entries = make(map[string]loginFailures, 16)
	}
	e := g.entries[ip]
	if !e.lastFailure.IsZero() && now.Sub(e.lastFailure) > loginFailureTTL {
		e.count = 0
	}
	e.count++
	e.lastFailure = now
	if e.count > loginMaxFailures {
		lock := loginLockoutStep << min(e.count-loginMaxFailures-1, 16)
		if lock > loginMaxLockout || lock <= 0 {
			lock = loginMaxLockout
		}
		e.lockedUntil = now.Add(lock)
	}
	// Prune before the updated entry is written back so this call's own entry
	// can never be swept out from under it.
	g.pruneLocked(now)
	g.entries[ip] = e
	if e.lockedUntil.After(now) {
		return e.lockedUntil.Sub(now)
	}
	return 0
}

// reset clears the history for ip after a successful login.
func (g *loginGuard) reset(ip string) {
	g.mu.Lock()
	delete(g.entries, ip)
	g.mu.Unlock()
}

// pruneLocked drops entries that are neither locked nor inside the failure
// window once the map outgrows its bound. Expiry alone is not enough: a scanner
// behind a rotating IP range would otherwise grow the map forever. The caller
// holds g.mu; deleting while ranging over the map is safe.
func (g *loginGuard) pruneLocked(now time.Time) {
	if len(g.entries) <= loginMaxTrackedIP {
		return
	}
	for ip, e := range g.entries {
		stale := e.lockedUntil.Before(now) && now.Sub(e.lastFailure) > loginFailureTTL
		if stale {
			delete(g.entries, ip)
		}
	}
}
