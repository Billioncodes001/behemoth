package server

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// authPageThrottle is a process-wide brake for traffic that leaves through the
// local forward proxy. Shared/rotating residential providers (Webshare et al.)
// meter authentication pages far harder than normal browsing and revoke proxy
// auth (HTTP 407, "client_connect_auth_revoked") once an account keeps hammering
// login/sign-up endpoints. The throttle therefore:
//
//   - counts auth-looking requests per target host in rolling minute/hour windows
//     and answers 429 with Retry-After instead of forwarding them,
//   - keeps a much more generous per-host burst cap for everything else (CONNECT
//     tunnels hide the path, so unknown traffic is only burst-limited),
//   - opens a cooldown for a host when an auth request is refused upstream
//     (407/429/403) so the agent stops instead of retrying in a tight loop.
//
// Configuration (env, all optional): BEHEMOTH_AUTH_THROTTLE=0 disables it,
// BEHEMOTH_AUTH_THROTTLE_PER_MINUTE / _PER_HOUR set the auth budget (defaults 6
// and 20), BEHEMOTH_AUTH_THROTTLE_HOST_PER_MINUTE the burst cap (default 180),
// BEHEMOTH_AUTH_THROTTLE_COOLDOWN_SECONDS the cooldown (default 1800).
type authPageThrottle struct {
	mu            sync.Mutex
	hosts         map[string]*authHostState
	now           func() time.Time
	perMinute     int
	perHour       int
	hostPerMinute int
	cooldown      time.Duration
	disabled      bool
}

type authHostState struct {
	authSent      []time.Time
	allSent       []time.Time
	cooldownUntil time.Time
}

func newAuthPageThrottle() *authPageThrottle {
	t := &authPageThrottle{
		hosts:         map[string]*authHostState{},
		now:           time.Now,
		perMinute:     envInt("BEHEMOTH_AUTH_THROTTLE_PER_MINUTE", 6),
		perHour:       envInt("BEHEMOTH_AUTH_THROTTLE_PER_HOUR", 20),
		hostPerMinute: envInt("BEHEMOTH_AUTH_THROTTLE_HOST_PER_MINUTE", 180),
		cooldown:      time.Duration(envInt("BEHEMOTH_AUTH_THROTTLE_COOLDOWN_SECONDS", 1800)) * time.Second,
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("BEHEMOTH_AUTH_THROTTLE"))) {
	case "0", "false", "off", "no":
		t.disabled = true
	}
	return t
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// authGate is the process-wide instance used by the forward proxy hooks.
var authGate = newAuthPageThrottle()

// authPagePath reports whether a request targets an authentication page whose
// traffic providers meter. Only navigational/POST requests count; assets and API
// calls do not.
func authPagePath(method, path string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "POST":
	default:
		return false
	}
	p := strings.ToLower(path)
	if p == "" || p == "/" {
		return false
	}
	for _, marker := range []string{
		"login", "log-in", "signin", "sign-in", "signup", "sign-up", "register",
		"registration", "password", "forgot", "reset", "otp", "mfa", "2fa",
		"/auth", "auth/", "session", "sso", "oauth",
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func normalizeAuthHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.TrimPrefix(h, "www.")
}

func dropBefore(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && !times[i].After(cutoff) {
		i++
	}
	if i == 0 {
		return times
	}
	return times[i:]
}

// state returns (creating if needed) the pruned counters for host. Caller must
// hold the mutex.
func (t *authPageThrottle) state(host string, now time.Time) *authHostState {
	st := t.hosts[host]
	if st == nil {
		st = &authHostState{}
		t.hosts[host] = st
	}
	st.authSent = dropBefore(st.authSent, now.Add(-time.Hour))
	st.allSent = dropBefore(st.allSent, now.Add(-time.Minute))
	return st
}

// gate decides whether a request may proceed. It returns HTTP 429, a Retry-After
// hint in seconds and an explanatory message when the request must wait.
func (t *authPageThrottle) gate(method, host, path string) (status, retrySeconds int, msg string) {
	if t == nil || t.disabled {
		return 0, 0, ""
	}
	h := normalizeAuthHost(host)
	if h == "" {
		return 0, 0, ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	st := t.state(h, now)

	if wait := st.cooldownUntil.Sub(now); wait > 0 {
		return 429, int(wait.Seconds()) + 1, fmt.Sprintf(
			"BEHEMOTH auth-page cooldown for %s: the proxy provider rejected or limited this host. Wait %s, or pause the task and resume later (never retry in a tight loop).",
			h, wait.Round(time.Second))
	}

	if t.hostPerMinute > 0 && len(st.allSent) >= t.hostPerMinute {
		wait := st.allSent[len(st.allSent)-t.hostPerMinute].Add(time.Minute).Sub(now)
		return 429, int(wait.Seconds()) + 1, fmt.Sprintf(
			"BEHEMOTH proxy burst cap for %s: %d requests in the last minute. Throttle the scanner/wordlist and retry.", h, t.hostPerMinute)
	}

	if authPagePath(method, path) {
		// authSent keeps an hour of history for the hourly budget; count the tail
		// that falls inside the minute window instead of the whole slice.
		authLastMinute := 0
		minuteCutoff := now.Add(-time.Minute)
		for i := len(st.authSent) - 1; i >= 0 && st.authSent[i].After(minuteCutoff); i-- {
			authLastMinute++
		}
		if t.perMinute > 0 && authLastMinute >= t.perMinute {
			wait := st.authSent[len(st.authSent)-t.perMinute].Add(time.Minute).Sub(now)
			return 429, int(wait.Seconds()) + 1, fmt.Sprintf(
				"BEHEMOTH auth-page budget for %s: %d login/sign-up requests in the last minute (limit %d/min, %d/hour through proxy providers). Wait before the next credential attempt.",
				h, authLastMinute, t.perMinute, t.perHour)
		}
		if t.perHour > 0 && len(st.authSent) >= t.perHour {
			wait := st.authSent[len(st.authSent)-t.perHour].Add(time.Hour).Sub(now)
			return 429, int(wait.Seconds()) + 1, fmt.Sprintf(
				"BEHEMOTH auth-page budget for %s exhausted: %d login/sign-up requests in the last hour. Record your attempts, disable the proxy for the credential phase, or resume later.",
				h, len(st.authSent))
		}
		st.authSent = append(st.authSent, now)
	}
	st.allSent = append(st.allSent, now)
	if len(t.hosts) > 512 {
		for k, v := range t.hosts {
			if v.cooldownUntil.Before(now) && len(v.allSent) == 0 && len(v.authSent) == 0 {
				delete(t.hosts, k)
			}
		}
	}
	return 0, 0, ""
}

// noteUpstream records an upstream failure. Provider auth revocation (407) and
// rate-limit/WAF answers on auth pages open a cooldown for the target host.
func (t *authPageThrottle) noteUpstream(host string, status int, method, path string) {
	if t == nil || t.disabled {
		return
	}
	h := normalizeAuthHost(host)
	if h == "" {
		return
	}
	if status != 407 && status != 429 && status != 403 {
		return
	}
	if status != 407 && !authPagePath(method, path) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	st := t.state(h, now)
	if until := now.Add(t.cooldown); until.After(st.cooldownUntil) {
		st.cooldownUntil = until
	}
}
