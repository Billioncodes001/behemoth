package server

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	proxyv2 "github.com/Autumn-27/behemoth/server/proxy/v2"
	"golang.org/x/net/proxy"
)

const (
	torManagedPrefix          = "tor-circuit-"
	torManagedHost            = "127.0.0.1"
	torManagedSocks           = 19050
	torManagedCtrl            = 19051
	torSystemSocks            = 9050
	settingTorMode            = "tor_pool_mode_v1"
	settingTorExclusiveActive = "tor_exclusive_active_v1"
	settingTorCircuitCount    = "tor_circuit_count_v1"
	settingTorSuspendedIDs    = "tor_suspended_proxy_ids_v1"
)

var (
	torMu               sync.Mutex
	torCmd              *exec.Cmd
	torNonceSeq         int64
	torSocksPort        = torManagedSocks
	torCtrlPort         = torManagedCtrl
	torExclusiveEntries []proxyv2.ProxyInfo
)

func findTorBinary() string {
	for _, cand := range []string{"tor", "/usr/bin/tor", "/usr/sbin/tor", "/opt/homebrew/bin/tor", "/usr/local/bin/tor"} {
		if p, err := exec.LookPath(cand); err == nil && p != "" {
			return p
		}
	}
	return ""
}

func ensureTorInstalled(ctx context.Context) (string, error) {
	if bin := findTorBinary(); bin != "" {
		return bin, nil
	}
	if runtime.GOOS == "linux" {
		isRoot := os.Geteuid() == 0
		canSudo := !isRoot && exec.Command("sudo", "-n", "true").Run() == nil
		if isRoot || canSudo {
			installCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			var cmd *exec.Cmd
			script := "export DEBIAN_FRONTEND=noninteractive; apt-get update -y -qq && apt-get install -y -qq tor"
			if isRoot {
				cmd = exec.CommandContext(installCtx, "bash", "-c", script)
			} else {
				cmd = exec.CommandContext(installCtx, "sudo", "-n", "bash", "-c", script)
			}
			_ = cmd.Run()
			if bin := findTorBinary(); bin != "" {
				return bin, nil
			}
		}
	}
	return "", fmt.Errorf("tor binary is not installed on this host (install via 'apt-get install -y tor' or 'brew install tor')")
}

func isLocalPortOpen(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(torManagedHost, strconv.Itoa(port)), 600*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (s *Server) torWorkDir() string {
	base := "./data"
	if s != nil && strings.TrimSpace(s.dataDir) != "" {
		base = s.dataDir
	}
	return filepath.Join(base, "tor")
}

func (s *Server) ensureManagedTorDaemon(ctx context.Context) (int, error) {
	torMu.Lock()
	defer torMu.Unlock()

	if isLocalPortOpen(torManagedSocks) {
		torSocksPort = torManagedSocks
		torCtrlPort = torManagedCtrl
		return torSocksPort, nil
	}

	bin, err := ensureTorInstalled(ctx)
	if err != nil {
		// If system tor is already listening on 9050 even without binary in PATH, use it.
		if isLocalPortOpen(torSystemSocks) {
			torSocksPort = torSystemSocks
			torCtrlPort = 0
			return torSocksPort, nil
		}
		return 0, err
	}

	workDir := s.torWorkDir()
	dataDir := filepath.Join(workDir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return 0, fmt.Errorf("create tor data dir: %w", err)
	}
	_ = os.Chmod(dataDir, 0o700)

	cookiePath := filepath.Join(workDir, "control_auth_cookie")
	torrcPath := filepath.Join(workDir, "torrc")
	logPath := filepath.Join(workDir, "tor.log")
	torrc := fmt.Sprintf(`DataDirectory %s
SocksPort %s:%d IsolateSOCKSAuth
ControlPort %s:%d
CookieAuthentication 1
CookieAuthFile %s
AvoidDiskWrites 1
NewCircuitPeriod 15
MaxCircuitDirtiness 120
Log notice file %s
`, dataDir, torManagedHost, torManagedSocks, torManagedHost, torManagedCtrl, cookiePath, logPath)

	if err := os.WriteFile(torrcPath, []byte(torrc), 0o600); err != nil {
		return 0, fmt.Errorf("write torrc: %w", err)
	}

	cmd := exec.Command(bin, "-f", torrcPath)
	if err := cmd.Start(); err != nil {
		if isLocalPortOpen(torSystemSocks) {
			torSocksPort = torSystemSocks
			torCtrlPort = 0
			return torSocksPort, nil
		}
		return 0, fmt.Errorf("start tor daemon: %w", err)
	}
	torCmd = cmd
	go func(c *exec.Cmd) { _ = c.Wait() }(cmd)

	// Wait up to 60s for Tor SOCKS port + bootstrap 100%
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		if isLocalPortOpen(torManagedSocks) {
			pct := s.readTorBootstrapPercent(cookiePath)
			if pct >= 100 {
				torSocksPort = torManagedSocks
				torCtrlPort = torManagedCtrl
				return torSocksPort, nil
			}
		}
		time.Sleep(800 * time.Millisecond)
	}

	if isLocalPortOpen(torManagedSocks) {
		torSocksPort = torManagedSocks
		torCtrlPort = torManagedCtrl
		return torSocksPort, nil
	}
	if isLocalPortOpen(torSystemSocks) {
		torSocksPort = torSystemSocks
		torCtrlPort = 0
		return torSocksPort, nil
	}
	return 0, fmt.Errorf("tor daemon started but SOCKS5 port did not become ready within 45s")
}

func (s *Server) readTorBootstrapPercent(cookiePath string) int {
	resp, err := sendTorControlCommand(torManagedCtrl, cookiePath, "GETINFO status/bootstrap-phase")
	if err != nil {
		return 0
	}
	idx := strings.Index(resp, "PROGRESS=")
	if idx < 0 {
		return 0
	}
	rest := resp[idx+len("PROGRESS="):]
	end := strings.IndexAny(rest, " \r\n")
	if end > 0 {
		rest = rest[:end]
	}
	n, _ := strconv.Atoi(strings.TrimSpace(rest))
	return n
}

func sendTorControlCommand(ctrlPort int, cookiePath, command string) (string, error) {
	if ctrlPort <= 0 {
		return "", fmt.Errorf("tor control port not configured")
	}
	cookieBytes, err := os.ReadFile(cookiePath)
	if err != nil {
		return "", err
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(torManagedHost, strconv.Itoa(ctrlPort)), 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	authHex := hex.EncodeToString(cookieBytes)
	payload := fmt.Sprintf("AUTHENTICATE %s\r\n%s\r\nQUIT\r\n", authHex, command)
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", err
	}
	var sb strings.Builder
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		sb.WriteString(sc.Text())
		sb.WriteByte('\n')
	}
	out := sb.String()
	if !strings.Contains(out, "250 ") && !strings.Contains(out, "250-") {
		return out, fmt.Errorf("unexpected control port reply: %s", firstLine(out, 160))
	}
	return out, nil
}

func stopManagedTorProcessLocked() {
	if torCmd != nil && torCmd.Process != nil {
		_ = torCmd.Process.Kill()
		torCmd = nil
	}
}

func probeSingleTorCircuit(ctx context.Context, px proxyv2.ProxyInfo) (bool, string, int64) {
	u, err := url.Parse(px.BuildProxyURL())
	if err != nil {
		return false, "", 0
	}
	dialer, err := proxy.FromURL(u, &net.Dialer{Timeout: 8 * time.Second})
	if err != nil {
		return false, "", 0
	}
	tr := &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 14 * time.Second}

	for _, ep := range []string{"https://ipv4.icanhazip.com", "https://api.ipify.org?format=json", "https://checkip.amazonaws.com"} {
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if rerr != nil {
			continue
		}
		t0 := time.Now()
		resp, derr := cl.Do(req)
		lat := time.Since(t0).Milliseconds()
		if derr != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var ipObj struct {
			IP string `json:"ip"`
		}
		ipStr := strings.TrimSpace(string(body))
		if json.Unmarshal(body, &ipObj) == nil && ipObj.IP != "" {
			ipStr = strings.TrimSpace(ipObj.IP)
		}
		if net.ParseIP(ipStr) != nil {
			return true, ipStr, lat
		}
	}
	return false, "", 0
}

func verifyTorCircuitsWithRetry(ctx context.Context, entries []proxyv2.ProxyInfo) []proxyv2.ProxyInfo {
	runPass := func() int {
		var wg sync.WaitGroup
		var mu sync.Mutex
		okCount := 0
		for i := range entries {
			if entries[i].Status == proxyv2.StatusHealthy && entries[i].ResponseIP != "" {
				mu.Lock()
				okCount++
				mu.Unlock()
				continue
			}
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				ok, ip, lat := probeSingleTorCircuit(ctx, entries[idx])
				now := time.Now()
				mu.Lock()
				entries[idx].LastChecked = now
				entries[idx].UpdatedAt = now
				if ok {
					entries[idx].Status = proxyv2.StatusHealthy
					entries[idx].ResponseIP = ip
					entries[idx].LatencyMS = lat
					entries[idx].Latency = time.Duration(lat) * time.Millisecond
					entries[idx].SuccessRate = 1.0
					entries[idx].ConsecutiveFailures = 0
					okCount++
				} else {
					entries[idx].Status = proxyv2.StatusUnhealthy
					entries[idx].ConsecutiveFailures++
				}
				mu.Unlock()
			}(i)
		}
		wg.Wait()
		return okCount
	}

	if ok := runPass(); ok == 0 && ctx.Err() == nil {
		// On cold boot, Tor's first circuit build can take an extra 2–3 seconds; retry once automatically.
		select {
		case <-ctx.Done():
		case <-time.After(2500 * time.Millisecond):
			runPass()
		}
	}
	for i := range entries {
		if entries[i].ResponseIP != "" {
			country, city := lookupQuickGeo(entries[i].ResponseIP)
			entries[i].Country = country
			entries[i].City = city
		}
	}
	return entries
}

func (s *Server) isExclusiveTorActive() bool {
	return s != nil && s.m != nil && s.m.IsExclusiveTorEnabled()
}

// shutdownExclusiveTor stops the standalone Exclusive Tor daemon and clears its
// routing state. Called automatically whenever the user switches Proxy Pool ON or
// configures a manual Static Global Proxy while Exclusive Tor was active.
func (s *Server) shutdownExclusiveTor() {
	torMu.Lock()
	torExclusiveEntries = nil
	stopManagedTorProcessLocked()
	torMu.Unlock()

	if s != nil && s.m != nil {
		if s.m.pg != nil {
			_ = s.m.pg.SetSetting(settingTorExclusiveActive, "false")
		}
		s.m.SetExclusiveTor(false, nil)
	}
}

// shutdownHybridTorIfPoolDisabled cleans up Hybrid Tor circuits and stops the
// managed Tor daemon when Proxy Pool is switched OFF while Hybrid Tor was running.
// probeExclusiveTorRecover drops a circuit that just failed and probes up to max
// remaining circuits, promoting the first that answers. One burned Tor exit must
// never strand the whole platform while sibling circuits are still alive. When no
// circuit answers it clears the rotation list, which leaves the fail-closed guard
// in charge instead of silently falling back to a direct (IP-revealing) dial.
func (s *Server) probeExclusiveTorRecover(dead string, max int) bool {
	if s == nil || s.m == nil || !s.m.IsExclusiveTorEnabled() {
		return false
	}
	if max < 1 {
		max = 1
	}
	candidates := s.m.PruneExclusiveTorCircuit(dead)
	alive := make([]string, 0, len(candidates))
	probed := 0
	for _, cand := range candidates {
		if probed >= max {
			alive = append(alive, cand)
			continue
		}
		probed++
		if s.runProxyProbe(serverContext(s), cand, "", s.m.egressProbes(), proxyPoolProbeTimeout).OK {
			alive = append(alive, cand)
		}
	}
	if len(alive) == 0 {
		s.m.SetExclusiveTor(true, nil)
		return false
	}
	s.m.SetExclusiveTor(true, alive)
	s.proxyReconnectSuccess()
	return true
}

func (s *Server) shutdownHybridTorIfPoolDisabled() {
	if ppV2 == nil || ppV2.Pool == nil {
		return
	}
	hasTorRows := false
	for _, px := range ppV2.Pool.GetProxies() {
		if strings.HasPrefix(px.ID, torManagedPrefix) {
			hasTorRows = true
			break
		}
	}
	if !hasTorRows {
		return
	}
	_ = ppV2.Pool.ReplaceManagedPrefixProxies(torManagedPrefix, nil, false)
	if !s.isExclusiveTorActive() {
		torMu.Lock()
		stopManagedTorProcessLocked()
		torMu.Unlock()
	}
}

func (s *Server) restoreLegacySuspendedProxies() {
	if ppV2 == nil || ppV2.Pool == nil || s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if raw, ok, _ := s.m.pg.GetSetting(settingTorSuspendedIDs); ok && strings.TrimSpace(raw) != "" {
		var prev []string
		if json.Unmarshal([]byte(raw), &prev) == nil && len(prev) > 0 {
			_ = ppV2.Pool.RestoreProxyIDs(prev)
		}
		_ = s.m.pg.SetSetting(settingTorSuspendedIDs, "")
	}
}

func (s *Server) restorePersistedTorOnBoot() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if v, ok, _ := s.m.pg.GetSetting(settingTorExclusiveActive); ok && v == "true" {
		count := 5
		if cv, cok, _ := s.m.pg.GetSetting(settingTorCircuitCount); cok {
			if n, err := strconv.Atoi(strings.TrimSpace(cv)); err == nil && n >= 1 && n <= 10 {
				count = n
			}
		}
		go func() {
			ctx, cancel := context.WithTimeout(s.ctx, 75*time.Second)
			defer cancel()
			if _, err := s.enableTorInPool(ctx, count, "exclusive"); err != nil {
				log.Printf("[tor] boot restore warning: %v", err)
			}
		}()
	}
}

func (s *Server) torStatusSnapshot() map[string]any {
	bin := findTorBinary()
	managedRunning := isLocalPortOpen(torManagedSocks)
	systemRunning := !managedRunning && isLocalPortOpen(torSystemSocks)
	activePort := 0
	if managedRunning {
		activePort = torManagedSocks
	} else if systemRunning {
		activePort = torSystemSocks
	}

	exclusiveActive := s.isExclusiveTorActive()
	mode := "exclusive"
	if s != nil && s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting(settingTorMode); ok && (v == "exclusive" || v == "hybrid") {
			mode = v
		}
	}

	var exitIPs []string
	circuitsTotal := 0
	circuitsHealthy := 0
	hybridPoolActive := false

	if exclusiveActive {
		mode = "exclusive"
		torMu.Lock()
		circuitsTotal = len(torExclusiveEntries)
		for _, px := range torExclusiveEntries {
			if px.Status == proxyv2.StatusHealthy && px.ResponseIP != "" {
				circuitsHealthy++
				exitIPs = append(exitIPs, px.ResponseIP)
			}
		}
		torMu.Unlock()
	} else if ppV2 != nil && ppV2.Pool != nil {
		cfg := ppV2.Pool.GetConfig()
		poolEnabled := cfg != nil && cfg.Enabled
		nonTorActive := 0
		for _, px := range ppV2.Pool.GetProxies() {
			if strings.HasPrefix(px.ID, torManagedPrefix) {
				circuitsTotal++
				if px.Status == proxyv2.StatusHealthy || px.Status == proxyv2.StatusInUse {
					circuitsHealthy++
					if px.ResponseIP != "" {
						exitIPs = append(exitIPs, px.ResponseIP)
					}
				}
			} else if px.Active && px.Status != proxyv2.StatusDisabled {
				nonTorActive++
			}
		}
		if poolEnabled && circuitsTotal > 0 {
			mode = "hybrid"
			hybridPoolActive = nonTorActive > 0
		}
	}

	torEnabled := exclusiveActive || (circuitsTotal > 0 && ppV2 != nil && ppV2.Pool != nil && ppV2.Pool.GetConfig().Enabled)

	return map[string]any{
		"installed":          bin != "",
		"binary_path":        bin,
		"daemon_running":     managedRunning || systemRunning,
		"managed_control":    managedRunning,
		"socks_port":         activePort,
		"mode":               mode,
		"enabled_in_pool":    torEnabled,
		"exclusive_active":   exclusiveActive,
		"hybrid_pool_active": hybridPoolActive,
		"circuits_total":     circuitsTotal,
		"circuits_healthy":   circuitsHealthy,
		"exit_ips":           exitIPs,
	}
}

func buildTorCircuitEntries(socksPort, count int, nonce string) []proxyv2.ProxyInfo {
	if count < 1 {
		count = 5
	}
	if count > 10 {
		count = 10
	}
	now := time.Now()
	entries := make([]proxyv2.ProxyInfo, 0, count)
	for i := 1; i <= count; i++ {
		id := fmt.Sprintf("%s%d", torManagedPrefix, i)
		entries = append(entries, proxyv2.ProxyInfo{
			ID:        id,
			Type:      proxyv2.ProxyTypeSOCKS5,
			Host:      torManagedHost,
			Port:      socksPort,
			Username:  fmt.Sprintf("behemoth-tor-c%d", i),
			Password:  nonce,
			Status:    proxyv2.StatusUntested,
			Active:    true,
			Name:      fmt.Sprintf("Tor Anonymity Circuit #%d", i),
			Notes:     "Free unlimited-bandwidth Tor SOCKS5 isolated circuit (IsolateSOCKSAuth)",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return entries
}

func (s *Server) enableTorInPool(ctx context.Context, circuits int, requestedMode ...string) (map[string]any, error) {
	if ppV2 == nil || ppV2.Pool == nil {
		return nil, fmt.Errorf("Proxy Pool v2 is not initialized")
	}
	mode := "exclusive"
	if s != nil && s.m != nil && s.m.pg != nil {
		if saved, ok, _ := s.m.pg.GetSetting(settingTorMode); ok && (saved == "exclusive" || saved == "hybrid") {
			mode = saved
		}
	}
	if len(requestedMode) > 0 {
		m := strings.ToLower(strings.TrimSpace(requestedMode[0]))
		if m == "exclusive" || m == "hybrid" {
			mode = m
		}
	}
	if circuits <= 0 {
		circuits = 5
	}
	if circuits > 10 {
		circuits = 10
	}
	if s != nil && s.m != nil && s.m.pg != nil {
		_ = s.m.pg.SetSetting(settingTorMode, mode)
		_ = s.m.pg.SetSetting(settingTorCircuitCount, strconv.Itoa(circuits))
	}

	// Clean up any legacy suspended pool rows so user/scraped proxies remain Healthy in the table!
	s.restoreLegacySuspendedProxies()

	socksPort, err := s.ensureManagedTorDaemon(ctx)
	if err != nil {
		return nil, err
	}

	torMu.Lock()
	torNonceSeq++
	nonce := fmt.Sprintf("n%d-%d", time.Now().Unix(), torNonceSeq)
	torMu.Unlock()

	entries := verifyTorCircuitsWithRetry(ctx, buildTorCircuitEntries(socksPort, circuits, nonce))
	healthy := 0
	var healthyURLs []string
	for _, e := range entries {
		if e.Status == proxyv2.StatusHealthy && e.ResponseIP != "" {
			healthy++
			healthyURLs = append(healthyURLs, e.BuildProxyURL())
		}
	}

	if mode == "exclusive" {
		// 1. Remove any hybrid tor-circuit-* entries from Proxy Pool and AUTO-DISABLE Proxy Pool
		//    (keeping all user/scraped proxies untouched and Healthy in the Proxy List!).
		_ = ppV2.Pool.ReplaceManagedPrefixProxies(torManagedPrefix, nil, false)
		poolCfg := ppV2.Pool.GetConfig()
		if poolCfg.Enabled {
			poolCfg.Enabled = false
			_ = ppV2.Pool.UpdateConfig(poolCfg)
		}
		s.syncProxyPoolNow()

		// 2. Activate standalone Exclusive Tor routing across all agents/tools/MCPs immediately!
		torMu.Lock()
		torExclusiveEntries = entries
		torMu.Unlock()
		if s != nil && s.m != nil {
			if s.m.pg != nil {
				_ = s.m.pg.SetSetting(settingTorExclusiveActive, "true")
			}
			s.m.SetExclusiveTor(true, healthyURLs)
		}
		if len(healthyURLs) > 0 {
			s.proxyReconnectSuccess()
		}
	} else {
		// Hybrid mode ("Tor + Pool Together"): clear standalone Exclusive Tor state,
		// insert verified Tor circuits alongside pool proxies, and enable Proxy Pool!
		torMu.Lock()
		torExclusiveEntries = nil
		torMu.Unlock()
		if s != nil && s.m != nil {
			if s.m.pg != nil {
				_ = s.m.pg.SetSetting(settingTorExclusiveActive, "false")
			}
			s.m.SetExclusiveTor(false, nil)
		}
		if err := ppV2.Pool.ReplaceManagedPrefixProxies(torManagedPrefix, entries, true); err != nil {
			return nil, err
		}
		poolCfg := ppV2.Pool.GetConfig()
		if !poolCfg.Enabled {
			poolCfg.Enabled = true
			_ = ppV2.Pool.UpdateConfig(poolCfg)
		}
		s.syncProxyPoolNow()
	}

	status := s.torStatusSnapshot()
	status["action"] = "enable_tor"
	status["tested_healthy"] = healthy
	return status, nil
}

func (s *Server) rotateTorIdentity(ctx context.Context) (map[string]any, error) {
	if ppV2 == nil || ppV2.Pool == nil {
		return nil, fmt.Errorf("Proxy Pool v2 is not initialized")
	}
	cookiePath := filepath.Join(s.torWorkDir(), "control_auth_cookie")
	newnymSent := false
	if isLocalPortOpen(torManagedCtrl) {
		if _, err := sendTorControlCommand(torManagedCtrl, cookiePath, "SIGNAL NEWNYM"); err == nil {
			newnymSent = true
		}
	}

	exclusive := s.isExclusiveTorActive()
	existingCount := 0
	if exclusive {
		torMu.Lock()
		existingCount = len(torExclusiveEntries)
		torMu.Unlock()
	} else {
		for _, px := range ppV2.Pool.GetProxies() {
			if strings.HasPrefix(px.ID, torManagedPrefix) {
				existingCount++
			}
		}
	}
	if existingCount == 0 {
		existingCount = 5
	}

	mode := "hybrid"
	if exclusive {
		mode = "exclusive"
	}
	status, err := s.enableTorInPool(ctx, existingCount, mode)
	if err != nil {
		return nil, err
	}
	status["action"] = "tor_newnym"
	status["signal_newnym_sent"] = newnymSent
	return status, nil
}

func (s *Server) disableTorInPool() (map[string]any, error) {
	if ppV2 == nil || ppV2.Pool == nil {
		return nil, fmt.Errorf("Proxy Pool v2 is not initialized")
	}
	s.restoreLegacySuspendedProxies()
	s.shutdownExclusiveTor()
	_ = ppV2.Pool.ReplaceManagedPrefixProxies(torManagedPrefix, nil, false)
	s.syncProxyPoolNow()

	status := s.torStatusSnapshot()
	status["action"] = "disable_tor"
	return status, nil
}

// HTTP Handlers under /api/v2/proxy-pool/tor/*

func (s *Server) handleTorStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.torStatusSnapshot())
}

func (s *Server) handleTorEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Circuits int    `json:"circuits"`
		Mode     string `json:"mode"` // "exclusive" (default: pause non-Tor proxies) | "hybrid" (use Tor + Pool proxies together)
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	out, err := s.enableTorInPool(r.Context(), req.Circuits, req.Mode)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleTorDisable(w http.ResponseWriter, r *http.Request) {
	out, err := s.disableTorInPool()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleTorNewnym(w http.ResponseWriter, r *http.Request) {
	out, err := s.rotateTorIdentity(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
