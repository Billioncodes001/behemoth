package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// The guard must let the first loginMaxFailures wrong passwords through and
// then lock the IP with a growing backoff. Everything here runs against the
// in-memory map only — no PostgreSQL involved.
func TestLoginGuardAllowsThenLocks(t *testing.T) {
	g := &loginGuard{}
	for i := 0; i < loginMaxFailures; i++ {
		if wait := g.fail("203.0.113.7"); wait > 0 {
			t.Fatalf("failure %d locked too early: wait=%v", i+1, wait)
		}
		if wait := g.retryAfter("203.0.113.7"); wait != 0 {
			t.Fatalf("failure %d: retryAfter=%v, want 0", i+1, wait)
		}
	}
	if wait := g.fail("203.0.113.7"); wait <= 0 {
		t.Fatalf("failure %d should start a lockout, wait=%v", loginMaxFailures+1, wait)
	}
	if wait := g.retryAfter("203.0.113.7"); wait <= 0 {
		t.Fatal("locked IP must report a positive retryAfter")
	}
}

// Each extra failure past the allowance doubles the lockout, up to the cap.
func TestLoginGuardBackoffGrowsAndCaps(t *testing.T) {
	g := &loginGuard{}
	for i := 0; i < loginMaxFailures; i++ {
		g.fail("203.0.113.8")
	}
	if first := g.fail("203.0.113.8"); first != loginLockoutStep {
		t.Fatalf("first lockout=%v, want %v", first, loginLockoutStep)
	}
	if second := g.fail("203.0.113.8"); second != 2*loginLockoutStep {
		t.Fatalf("second lockout=%v, want %v", second, 2*loginLockoutStep)
	}
	// Hammer past the cap: every further lockout must stay at the maximum.
	for i := 0; i < 20; i++ {
		if wait := g.fail("203.0.113.8"); wait > loginMaxLockout {
			t.Fatalf("lockout %v exceeds cap %v", wait, loginMaxLockout)
		}
	}
}

// A successful login clears the failure history.
func TestLoginGuardReset(t *testing.T) {
	g := &loginGuard{}
	for i := 0; i < loginMaxFailures; i++ {
		g.fail("203.0.113.9")
	}
	g.reset("203.0.113.9")
	if wait := g.retryAfter("203.0.113.9"); wait != 0 {
		t.Fatalf("reset must clear the IP, retryAfter=%v", wait)
	}
	if wait := g.fail("203.0.113.9"); wait != 0 {
		t.Fatalf("count must restart after reset, wait=%v", wait)
	}
}

// An expired lockout must clear itself instead of requiring a fresh fail/reset.
func TestLoginGuardExpiredLockoutClears(t *testing.T) {
	g := &loginGuard{entries: map[string]loginFailures{
		"203.0.113.10": {count: 6, lastFailure: time.Now().Add(-time.Hour), lockedUntil: time.Now().Add(-time.Second)},
	}}
	if wait := g.retryAfter("203.0.113.10"); wait != 0 {
		t.Fatalf("expired lockout still blocks: wait=%v", wait)
	}
	if _, ok := g.entries["203.0.113.10"]; ok {
		t.Fatal("expired entry must be deleted on read")
	}
}

// The map must not grow without bound: once the bound is passed, stale entries
// (old failure window, no active lockout) are swept and the entry just written
// survives.
func TestLoginGuardPrunesStaleEntries(t *testing.T) {
	g := &loginGuard{entries: make(map[string]loginFailures)}
	stale := time.Now().Add(-2 * loginFailureTTL)
	for i := 0; i < loginMaxTrackedIP+10; i++ {
		g.entries[fmt.Sprintf("198.51.100.%d", i)] = loginFailures{count: 1, lastFailure: stale}
	}
	g.fail("10.9.9.9")
	if len(g.entries) != 1 {
		t.Fatalf("prune left %d entries, want only the fresh one", len(g.entries))
	}
	if _, ok := g.entries["10.9.9.9"]; !ok {
		t.Fatal("the entry being written must survive pruning")
	}
}

// Only HS256 may verify: the same key re-signed under HS512 (accepted by the
// old bare-HMAC check) must now be rejected.
func TestVerifyJWTPinsHS256(t *testing.T) {
	s := &Server{jwtKey: []byte("test-only-signing-key-32-characters")}

	hs256, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	hs512, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{
		Subject: "ARTEX", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyJWT(hs256, s.jwtKey) {
		t.Fatal("HS256 token must verify")
	}
	if verifyJWT(hs512, s.jwtKey) {
		t.Fatal("HS512 token must be rejected (algorithm pinned to HS256)")
	}
	if verifyJWT("", s.jwtKey) || verifyJWT("   ", s.jwtKey) {
		t.Fatal("empty token must be rejected")
	}
}

// Handler-level: after loginMaxFailures+1 wrong passwords the next attempt gets
// 429 with a Retry-After header instead of another bcrypt compare, and the lock
// holds even for the correct password until the lockout expires. Requires a
// live PostgreSQL like the rest of the server suite.
func TestAuthLoginRateLimited(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m, jwtKey: []byte("test-only-signing-key-32-characters")}

	login := func(password string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		body := strings.NewReader(`{"username":"ARTEX","password":"` + password + `"}`)
		s.authLogin(w, httptest.NewRequest("POST", "/api/auth/login", body))
		return w
	}

	for i := 0; i < loginMaxFailures+1; i++ {
		if w := login("wrong-password"); w.Code != 401 {
			t.Fatalf("attempt %d: status=%d want 401", i+1, w.Code)
		}
	}
	w := login("wrong-password")
	if w.Code != 429 {
		t.Fatalf("after %d failures expected 429, got %d: %s", loginMaxFailures+1, w.Code, w.Body.String())
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Fatal("429 must carry Retry-After")
	}
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || payload.Code != "too_many_attempts" {
		t.Fatalf("429 body must carry the product-error code, got %q err=%v", w.Body.String(), err)
	}
	if w := login("correct horse battery staple"); w.Code != 429 {
		t.Fatalf("locked IP must stay locked even with the right password, got %d", w.Code)
	}
}
