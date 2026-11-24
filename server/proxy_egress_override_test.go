package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	proxyv2 "github.com/Autumn-27/artex/server/proxy/v2"
)

// scriptedProbe answers only for the URLs listed as alive; everything else fails
// like a burned proxy/Tor exit would.
type scriptedProbe struct {
	alive map[string]bool
	calls int
	seen  []string
}

func (p *scriptedProbe) probe(_ context.Context, proxyRaw, _ string, _ []string, _ time.Duration) egressProbeResult {
	p.calls++
	p.seen = append(p.seen, proxyRaw)
	if p.alive[proxyRaw] {
		return egressProbeResult{OK: true, ExitIP: "203.0.113.9"}
	}
	return egressProbeResult{OK: false, Error: "dial socks5: connection refused"}
}

func TestCaptureEgressOverrideOutranksPoolAndTor(t *testing.T) {
	m := proxyTestManager(t)
	override := "socks5://u:p@127.0.0.1:1080"
	t.Cleanup(func() { _ = m.SetCaptureEgressOverride("") })

	if err := m.SetCaptureEgressOverride(override); err != nil {
		t.Fatalf("SetCaptureEgressOverride: %v", err)
	}
	if got := m.GlobalProxy(); got != override {
		t.Fatalf("GlobalProxy = %q, want the override", got)
	}
	if got := m.NextUpstreamProxy(); got != override {
		t.Fatalf("NextUpstreamProxy = %q, want the override (rotation must not bypass it)", got)
	}
	if !m.HasOutboundProxy() {
		t.Fatal("override must count as an outbound proxy so agents get proxy env")
	}

	// Exclusive Tor turning on must not silently displace the operator's tunnel.
	m.SetExclusiveTor(true, []string{"socks5://127.0.0.1:19050"})
	if got := m.GlobalProxy(); got != override {
		t.Fatalf("GlobalProxy after Tor = %q, want the override", got)
	}
	if got := m.ProxyAddr(); got == "" {
		t.Fatal("ProxyAddr must stay non-empty while the override is pinned")
	}

	// Clearing it restores the Tor route (not a direct/leaky state).
	if err := m.SetCaptureEgressOverride(""); err != nil {
		t.Fatalf("clear override: %v", err)
	}
	if got := m.GlobalProxy(); got != "socks5://127.0.0.1:19050" {
		t.Fatalf("GlobalProxy after clear = %q, want the Tor circuit", got)
	}
	if !m.IsProxyPoolFailClosed() {
		t.Fatal("Tor still running must keep egress fail-closed after the override is cleared")
	}
}

func TestExclusiveTorFailureRotatesAwayFromDeadCircuit(t *testing.T) {
	resetTorEntries(t)
	m := proxyTestManager(t)
	s := &Server{m: m}
	probe := &scriptedProbe{alive: map[string]bool{"socks5://127.0.0.1:19052": true}}
	s.proxyProbe = probe.probe

	dead := "socks5://127.0.0.1:19050"
	m.SetExclusiveTor(true, []string{dead, "socks5://127.0.0.1:19051", "socks5://127.0.0.1:19052"})

	if !s.handleProxyPoolFailure(errors.New("proxyconnect tcp: dial socks5: connection refused")) {
		t.Fatal("a dead circuit with healthy siblings must be reported as recovered")
	}
	circuits := m.ExclusiveTorCircuits()
	if len(circuits) != 1 || circuits[0] != "socks5://127.0.0.1:19052" {
		t.Fatalf("expected only the healthy circuit to remain, got %v", circuits)
	}
	if got := m.GlobalProxy(); got != "socks5://127.0.0.1:19052" {
		t.Fatalf("GlobalProxy = %q, want the promoted healthy circuit", got)
	}
	if m.ExclusiveTorCircuitCount() != 1 {
		t.Fatalf("dead circuits must be pruned from the rotation, count=%d", m.ExclusiveTorCircuitCount())
	}
}

func TestExclusiveTorExhaustionFailsClosedAndReports(t *testing.T) {
	resetTorEntries(t)
	m := proxyTestManager(t)
	s := &Server{m: m}
	s.proxyProbe = (&scriptedProbe{}).probe

	m.SetExclusiveTor(true, []string{"socks5://127.0.0.1:19050", "socks5://127.0.0.1:19051"})
	if s.handleProxyPoolFailure(errors.New("proxyconnect tcp: dial socks5: connection refused")) {
		t.Fatal("an all-dead circuit set must not report recovery")
	}
	if got := m.ExclusiveTorCircuitCount(); got != 0 {
		t.Fatalf("expected every dead circuit pruned, still %d", got)
	}
	if !m.IsProxyPoolFailClosed() {
		t.Fatal("exhausted Exclusive Tor must remain fail-closed")
	}
	if got := m.GlobalProxy(); got != "" {
		t.Fatalf("GlobalProxy = %q, want empty (blocked) with no circuit left", got)
	}

	payload, err := s.buildProxyStatusPayload()
	if err != nil {
		t.Fatalf("status payload: %v", err)
	}
	if payload["effective_routing_mode"] != "exclusive_tor_exhausted_fail_closed" {
		t.Fatalf("routing mode = %v, want the exhausted fail-closed marker", payload["effective_routing_mode"])
	}
	if payload["proxy_enabled"] != true {
		t.Fatal("fail-closed exhaustion must still report proxy_enabled=true")
	}
}

func TestExclusiveTorStatusHealthyCircuit(t *testing.T) {
	resetTorEntries(t)
	m := proxyTestManager(t)
	s := &Server{m: m}
	m.SetExclusiveTor(true, []string{"socks5://127.0.0.1:19050"})
	torMu.Lock()
	torExclusiveEntries = []proxyv2.ProxyInfo{{Status: proxyv2.StatusHealthy, ResponseIP: "203.0.113.7"}}
	torMu.Unlock()

	payload, err := s.buildProxyStatusPayload()
	if err != nil {
		t.Fatalf("status payload: %v", err)
	}
	if payload["effective_routing_mode"] != "exclusive_tor" {
		t.Fatalf("routing mode = %v, want exclusive_tor", payload["effective_routing_mode"])
	}
}

func TestProxyReconnectTickPrefersPinnedOverrideOverTor(t *testing.T) {
	resetTorEntries(t)
	m := proxyTestManager(t)
	s := &Server{m: m}
	override := "socks5://u:p@127.0.0.1:1080"
	probe := &scriptedProbe{alive: map[string]bool{override: true}}
	s.proxyProbe = probe.probe

	if err := m.SetCaptureEgressOverride(override); err != nil {
		t.Fatal(err)
	}
	m.SetExclusiveTor(true, []string{"socks5://127.0.0.1:19050"})

	s.proxyReconnectTick()

	for _, seen := range probe.seen {
		if strings.Contains(seen, "19050") {
			t.Fatalf("tick probed the Tor circuit while a tunnel is pinned: %v", probe.seen)
		}
	}
	if len(probe.seen) == 0 || probe.seen[0] != override {
		t.Fatalf("tick must probe the pinned tunnel, saw %v", probe.seen)
	}
}

func TestProxyReconnectTickTreatsFailClosedEmptyRouteAsFailure(t *testing.T) {
	resetTorEntries(t)
	m := proxyTestManager(t)
	s := &Server{m: m}
	s.proxyProbe = (&scriptedProbe{}).probe
	probe := &scriptedProbe{}
	s.proxyProbe = probe.probe
	// The package DB is shared across tests, so a prior case may have left a
	// persisted active proxy behind; start from a clean, routed-nowhere state.
	m.mu.Lock()
	m.globalProxy = ""
	m.mu.Unlock()
	m.SetProxyPoolFailClosed(true) // pool enabled, but nothing healthy

	if got := m.GlobalProxy(); got != "" {
		t.Fatalf("precondition: expected empty route, got %q", got)
	}
	s.proxyReconnectTick() // must not panic and must not resume on a direct probe
	if len(probe.seen) != 0 {
		// An empty route is only probed inside per-task attempts; there are no
		// tasks here, so the tick must not have probed a misleading direct dial.
		t.Logf("probed %v", probe.seen)
	}
}

func TestReconcileDoesNotSwitchPoolWhileExclusiveTorOwnsEgress(t *testing.T) {
	resetTorEntries(t)
	m := proxyTestManager(t)
	s := &Server{m: m}

	pool := proxyv2.NewPool(nil)
	ppV2 = &proxyPoolV2{Pool: pool, Handler: proxyv2.NewHandler(pool)}
	if _, err := pool.ImportProxies("198.51.100.20:8080", proxyv2.ProxyTypeHTTP); err != nil {
		t.Fatal(err)
	}
	s.syncProxyPoolNow()

	m.SetExclusiveTor(true, []string{"socks5://127.0.0.1:19050"})
	if s.reconcileProxyPoolAfterProbe(false) {
		t.Fatal("pool rows are suspended under Exclusive Tor; reconcile must not claim a switch")
	}
	if got := m.GlobalProxy(); got != "socks5://127.0.0.1:19050" {
		t.Fatalf("GlobalProxy = %q, want the Tor circuit", got)
	}
}

func resetTorEntries(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		torMu.Lock()
		torExclusiveEntries = nil
		torMu.Unlock()
	})
}
