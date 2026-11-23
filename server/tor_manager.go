package server

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	proxyv2 "github.com/Autumn-27/artex/server/proxy/v2"
)

const (
	torManagedPrefix        = "tor-circuit-"
	torManagedHost          = "127.0.0.1"
	torManagedSocks         = 19050
	torManagedCtrl          = 19051
	torSystemSocks          = 9050
	settingTorMode          = "tor_pool_mode_v1"
	settingTorSuspendedIDs  = "tor_suspended_proxy_ids_v1"
)

var (
	torMu        sync.Mutex
	torCmd       *exec.Cmd
	torNonceSeq  int64
	torSocksPort = torManagedSocks
	torCtrlPort  = torManagedCtrl
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

	// Wait up to 45s for Tor SOCKS port + bootstrap 100%
	deadline := time.Now().Add(45 * time.Second)
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

	torInPool := 0
	torHealthy := 0
	nonTorActive := 0
	var exitIPs []string
	poolEnabled := false
	if ppV2 != nil && ppV2.Pool != nil {
		cfg := ppV2.Pool.GetConfig()
		poolEnabled = cfg != nil && cfg.Enabled
		for _, px := range ppV2.Pool.GetProxies() {
			if strings.HasPrefix(px.ID, torManagedPrefix) {
				torInPool++
				if px.Status == proxyv2.StatusHealthy || px.Status == proxyv2.StatusInUse {
					torHealthy++
					if px.ResponseIP != "" {
						exitIPs = append(exitIPs, px.ResponseIP)
					}
				}
			} else if px.Active && px.Status != proxyv2.StatusDisabled {
				nonTorActive++
			}
		}
	}
	mode := "exclusive"
	var suspendedIDs []string
	if s != nil && s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting(settingTorMode); ok && (v == "exclusive" || v == "hybrid") {
			mode = v
		}
		if raw, ok, _ := s.m.pg.GetSetting(settingTorSuspendedIDs); ok && strings.TrimSpace(raw) != "" {
			_ = json.Unmarshal([]byte(raw), &suspendedIDs)
		}
	}

	return map[string]any{
		"installed":            bin != "",
		"binary_path":          bin,
		"daemon_running":       managedRunning || systemRunning,
		"managed_control":      managedRunning,
		"socks_port":           activePort,
		"mode":                 mode,
		"enabled_in_pool":      poolEnabled && torInPool > 0,
		"hybrid_pool_active":   poolEnabled && torInPool > 0 && nonTorActive > 0,
		"suspended_pool_count": len(suspendedIDs),
		"circuits_total":       torInPool,
		"circuits_healthy":     torHealthy,
		"exit_ips":             exitIPs,
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
			Username:  fmt.Sprintf("artex-tor-c%d", i),
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
	if s != nil && s.m != nil && s.m.pg != nil {
		_ = s.m.pg.SetSetting(settingTorMode, mode)
	}

	if circuits <= 0 {
		circuits = 5
	}
	if circuits > 10 {
		circuits = 10
	}
	socksPort, err := s.ensureManagedTorDaemon(ctx)
	if err != nil {
		return nil, err
	}

	// Handle coexistence cleanly:
	// - "exclusive" (default): temporarily pause non-Tor proxies (remembering their IDs)
	//   so 100% of scanning bandwidth routes through free Tor circuits ($0 cost) and running
	//   agents switch to Tor immediately on their very next request!
	// - "hybrid": restore any previously Tor-suspended proxies so both Tor circuits and
	//   pool proxies coexist in rotation / smart failover!
	if mode == "exclusive" {
		if suspended, _ := ppV2.Pool.SuspendNonPrefixProxies(torManagedPrefix); len(suspended) > 0 && s != nil && s.m != nil && s.m.pg != nil {
			var prev []string
			if raw, ok, _ := s.m.pg.GetSetting(settingTorSuspendedIDs); ok && raw != "" {
				_ = json.Unmarshal([]byte(raw), &prev)
			}
			merged := append(prev, suspended...)
			b, _ := json.Marshal(merged)
			_ = s.m.pg.SetSetting(settingTorSuspendedIDs, string(b))
		}
	} else if mode == "hybrid" && s != nil && s.m != nil && s.m.pg != nil {
		if raw, ok, _ := s.m.pg.GetSetting(settingTorSuspendedIDs); ok && strings.TrimSpace(raw) != "" {
			var prev []string
			if json.Unmarshal([]byte(raw), &prev) == nil && len(prev) > 0 {
				_ = ppV2.Pool.RestoreProxyIDs(prev)
			}
			_ = s.m.pg.SetSetting(settingTorSuspendedIDs, "")
		}
	}

	torMu.Lock()
	torNonceSeq++
	nonce := fmt.Sprintf("n%d-%d", time.Now().Unix(), torNonceSeq)
	torMu.Unlock()

	entries := buildTorCircuitEntries(socksPort, circuits, nonce)
	if err := ppV2.Pool.ReplaceManagedPrefixProxies(torManagedPrefix, entries, true); err != nil {
		return nil, err
	}

	testCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	results, _ := ppV2.Pool.TestAllProxies(testCtx)
	cancel()

	s.syncProxyPoolNow()
	healthy := 0
	for _, r := range results {
		if strings.HasPrefix(r.ProxyID, torManagedPrefix) && r.Success {
			healthy++
		}
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

	// Count existing Tor circuits in pool (or default to 5 if none yet)
	existingCount := 0
	for _, px := range ppV2.Pool.GetProxies() {
		if strings.HasPrefix(px.ID, torManagedPrefix) {
			existingCount++
		}
	}
	if existingCount == 0 {
		existingCount = 5
	}

	socksPort, err := s.ensureManagedTorDaemon(ctx)
	if err != nil {
		return nil, err
	}

	// Rotating the SOCKS5 IsolateSOCKSAuth password guarantees fresh Tor exit
	// circuits immediately, even inside Tor's 10-second NEWNYM rate-limit window!
	torMu.Lock()
	torNonceSeq++
	nonce := fmt.Sprintf("n%d-%d", time.Now().UnixNano(), torNonceSeq)
	torMu.Unlock()

	entries := buildTorCircuitEntries(socksPort, existingCount, nonce)
	if err := ppV2.Pool.ReplaceManagedPrefixProxies(torManagedPrefix, entries, true); err != nil {
		return nil, err
	}

	testCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	_, _ = ppV2.Pool.TestAllProxies(testCtx)
	cancel()

	s.syncProxyPoolNow()
	status := s.torStatusSnapshot()
	status["action"] = "tor_newnym"
	status["signal_newnym_sent"] = newnymSent
	return status, nil
}

func (s *Server) disableTorInPool() (map[string]any, error) {
	if ppV2 == nil || ppV2.Pool == nil {
		return nil, fmt.Errorf("Proxy Pool v2 is not initialized")
	}
	// Restore any non-Tor proxies that were temporarily suspended by Exclusive Tor mode!
	if s != nil && s.m != nil && s.m.pg != nil {
		if raw, ok, _ := s.m.pg.GetSetting(settingTorSuspendedIDs); ok && strings.TrimSpace(raw) != "" {
			var prev []string
			if json.Unmarshal([]byte(raw), &prev) == nil && len(prev) > 0 {
				_ = ppV2.Pool.RestoreProxyIDs(prev)
			}
			_ = s.m.pg.SetSetting(settingTorSuspendedIDs, "")
		}
	}
	if err := ppV2.Pool.ReplaceManagedPrefixProxies(torManagedPrefix, nil, false); err != nil {
		return nil, err
	}
	torMu.Lock()
	if torCmd != nil && torCmd.Process != nil {
		_ = torCmd.Process.Kill()
		torCmd = nil
	}
	torMu.Unlock()

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
