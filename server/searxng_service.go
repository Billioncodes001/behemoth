package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/behemoth/server/search"
)

var (
	searxngProvisionMu   sync.Mutex
	searxngProvisioning  atomic.Bool
	searxngLastProvision atomic.Int64
)

func autoLocalSearXNGDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("BEHEMOTH_SEARXNG")))
	if v == "0" || v == "false" || v == "off" || v == "disabled" {
		return true
	}
	// Do not pull/launch background services inside `go test` runs.
	if flag.Lookup("test.v") != nil {
		return true
	}
	return false
}

// startLocalSearXNGSupervisor ensures the self-hosted SearXNG meta-search service
// runs automatically on the same host (127.0.0.1:8888) and stays registered in
// s.searchOrchestrator with zero manual URL configuration.
func (s *Server) startLocalSearXNGSupervisor(ctx context.Context) {
	if autoLocalSearXNGDisabled() || runtime.GOOS == "windows" {
		return
	}
	go func() {
		s.ensureLocalSearXNGService(ctx)
		ticker := time.NewTicker(90 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if localURL := search.DetectLocalSearXNGForce(); localURL != "" {
					if s.searchOrchestrator != nil {
						s.searchOrchestrator.UpdateEngine("searxng", localURL)
					}
					continue
				}
				s.ensureLocalSearXNGService(ctx)
			}
		}
	}()
}

// ensureLocalSearXNGReady waits briefly (or triggers provisioning) when a caller
// explicitly targets `engine="searxng"` right after startup.
func (s *Server) ensureLocalSearXNGReady(ctx context.Context, maxWait time.Duration) string {
	if localURL := search.DetectLocalSearXNGForce(); localURL != "" {
		if s.searchOrchestrator != nil {
			s.searchOrchestrator.UpdateEngine("searxng", localURL)
		}
		return localURL
	}
	if autoLocalSearXNGDisabled() || runtime.GOOS == "windows" {
		return ""
	}
	go s.ensureLocalSearXNGService(s.ctx)
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(1200 * time.Millisecond):
		}
		if localURL := search.DetectLocalSearXNGForce(); localURL != "" {
			if s.searchOrchestrator != nil {
				s.searchOrchestrator.UpdateEngine("searxng", localURL)
			}
			return localURL
		}
		if !searxngProvisioning.Load() && time.Since(time.Unix(searxngLastProvision.Load(), 0)) < 15*time.Second {
			break
		}
	}
	return search.DetectLocalSearXNGForce()
}

func (s *Server) ensureLocalSearXNGService(ctx context.Context) {
	if localURL := search.DetectLocalSearXNGForce(); localURL != "" {
		if s.searchOrchestrator != nil {
			s.searchOrchestrator.UpdateEngine("searxng", localURL)
		}
		return
	}

	if !searxngProvisionMu.TryLock() {
		return
	}
	defer searxngProvisionMu.Unlock()

	// Double-check after acquiring lock.
	if localURL := search.DetectLocalSearXNGForce(); localURL != "" {
		if s.searchOrchestrator != nil {
			s.searchOrchestrator.UpdateEngine("searxng", localURL)
		}
		return
	}

	searxngProvisioning.Store(true)
	defer func() {
		searxngLastProvision.Store(time.Now().Unix())
		searxngProvisioning.Store(false)
	}()

	cfgDir, settingsPath, err := s.writeLocalSearXNGConfig()
	if err != nil {
		log.Printf("[searxng] failed to prepare settings.yml: %v", err)
		return
	}

	// Path 1: Official SearXNG Docker container bound to 127.0.0.1:8888.
	if localURL := s.tryProvisionDockerSearXNG(ctx, cfgDir); localURL != "" {
		if s.searchOrchestrator != nil {
			s.searchOrchestrator.UpdateEngine("searxng", localURL)
		}
		log.Printf("[searxng] Self-hosted SearXNG Docker service active at %s", localURL)
		return
	}

	// Path 2: Native local Python SearXNG daemon on 127.0.0.1:8888 (when Docker is unavailable).
	if localURL := s.tryProvisionPythonSearXNG(ctx, settingsPath); localURL != "" {
		if s.searchOrchestrator != nil {
			s.searchOrchestrator.UpdateEngine("searxng", localURL)
		}
		log.Printf("[searxng] Self-hosted SearXNG Python service active at %s", localURL)
		return
	}

	log.Printf("[searxng] Auto-provisioning finished without a reachable local listener on 127.0.0.1:8888")
}

func (s *Server) writeLocalSearXNGConfig() (string, string, error) {
	baseDir := s.dataDir
	if strings.TrimSpace(baseDir) == "" {
		baseDir = "data"
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", "", err
	}
	cfgDir := filepath.Join(absBase, "searxng")
	if err := os.MkdirAll(cfgDir, 0o777); err != nil {
		return "", "", err
	}
	_ = os.Chmod(cfgDir, 0o777)

	// Also repair legacy /opt/behemoth/searxng permissions if created with 0600 earlier.
	if st, err := os.Stat("/opt/behemoth/searxng/settings.yml"); err == nil && !st.IsDir() {
		_ = os.Chmod("/opt/behemoth/searxng", 0o755)
		_ = os.Chmod("/opt/behemoth/searxng/settings.yml", 0o644)
	}

	settingsPath := filepath.Join(cfgDir, "settings.yml")
	if st, err := os.Stat(settingsPath); err == nil && st.Size() > 0 {
		_ = os.Chmod(settingsPath, 0o644)
		return cfgDir, settingsPath, nil
	}

	secretBuf := make([]byte, 24)
	_, _ = rand.Read(secretBuf)
	secret := hex.EncodeToString(secretBuf)
	if secret == "" {
		secret = "behemoth-searxng-local-secret-2026"
	}

	yml := fmt.Sprintf(`use_default_settings: true

server:
  secret_key: "%s"
  limiter: false
  image_proxy: false
  base_url: http://127.0.0.1:8888/

search:
  safe_search: 0
  formats:
    - html
    - json
`, secret)

	if err := os.WriteFile(settingsPath, []byte(yml), 0o644); err != nil {
		return "", "", err
	}
	_ = os.Chmod(settingsPath, 0o644)
	return cfgDir, settingsPath, nil
}

func (s *Server) tryProvisionDockerSearXNG(ctx context.Context, cfgDir string) string {
	if _, err := exec.LookPath("docker"); err != nil {
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			if _, aptErr := exec.LookPath("apt-get"); aptErr == nil {
				log.Printf("[searxng] Installing docker.io for local self-hosted SearXNG...")
				installCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
				cmd := exec.CommandContext(installCtx, "bash", "-c",
					"export DEBIAN_FRONTEND=noninteractive; apt-get update -y -qq && apt-get install -y -qq docker.io && (systemctl enable --now docker || service docker start || true)")
				_ = cmd.Run()
				cancel()
			}
		}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return ""
	}

	infoCtx, cancelInfo := context.WithTimeout(ctx, 8*time.Second)
	if err := exec.CommandContext(infoCtx, "docker", "info").Run(); err != nil {
		cancelInfo()
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			_ = exec.CommandContext(ctx, "bash", "-c", "systemctl start docker || service docker start || true").Run()
		}
		infoCtx2, cancelInfo2 := context.WithTimeout(ctx, 8*time.Second)
		err2 := exec.CommandContext(infoCtx2, "docker", "info").Run()
		cancelInfo2()
		if err2 != nil {
			return ""
		}
	} else {
		cancelInfo()
	}

	// Check if container `behemoth-searxng` already exists; start it first.
	inspectOut, _ := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=^/behemoth-searxng$", "--format", "{{.Names}}").Output()
	if strings.TrimSpace(string(inspectOut)) == "behemoth-searxng" {
		_ = exec.CommandContext(ctx, "docker", "start", "behemoth-searxng").Run()
		if localURL := waitSearXNGHealthy(ctx, 10*time.Second); localURL != "" {
			return localURL
		}
		// Existing container failed health checks (e.g., stale 0600 mount); recreate cleanly.
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", "behemoth-searxng").Run()
	}

	log.Printf("[searxng] Starting local SearXNG container on 127.0.0.1:8888...")
	runCtx, cancelRun := context.WithTimeout(ctx, 3*time.Minute)
	runOut, err := exec.CommandContext(runCtx, "docker", "run", "-d",
		"--name", "behemoth-searxng",
		"--restart", "unless-stopped",
		"-p", "127.0.0.1:8888:8080",
		"-v", cfgDir+":/etc/searxng:rw",
		"-e", "SEARXNG_BASE_URL=http://127.0.0.1:8888/",
		"searxng/searxng:latest",
	).CombinedOutput()
	cancelRun()
	if err != nil {
		log.Printf("[searxng] docker run failed: %v (%s)", err, firstLine(string(runOut), 200))
		return ""
	}
	return waitSearXNGHealthy(ctx, 35*time.Second)
}

func (s *Server) tryProvisionPythonSearXNG(ctx context.Context, settingsPath string) string {
	if _, err := exec.LookPath("python3"); err != nil {
		return ""
	}
	baseDir := s.dataDir
	if strings.TrimSpace(baseDir) == "" {
		baseDir = "data"
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return ""
	}
	srcDir := filepath.Join(absBase, "searxng-src")
	venvDir := filepath.Join(absBase, "searxng-venv")
	pyBin := filepath.Join(venvDir, "bin", "python")

	if _, stErr := os.Stat(pyBin); stErr != nil {
		log.Printf("[searxng] Docker unavailable; provisioning local Python SearXNG service on 127.0.0.1:8888...")
		setupCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		script := fmt.Sprintf(`
			set -e
			if [ "$(id -u)" -eq 0 ] && command -v apt-get >/dev/null 2>&1; then
				export DEBIAN_FRONTEND=noninteractive
				apt-get install -y -qq git python3-venv python3-pip python3-dev build-essential libxml2-dev libxslt1-dev zlib1g-dev >/dev/null 2>&1 || true
			fi
			if [ ! -d %q ]; then
				git clone --depth 1 https://github.com/searxng/searxng.git %q
			fi
			python3 -m venv %q
			%q -m pip install --quiet --upgrade pip setuptools wheel pyyaml
			%q -m pip install --quiet -r %q/requirements.txt
			%q -m pip install --quiet --no-build-isolation --no-deps -e %q
		`, srcDir, srcDir, venvDir, pyBin, pyBin, srcDir, pyBin, srcDir)
		out, err := exec.CommandContext(setupCtx, "bash", "-c", script).CombinedOutput()
		cancel()
		if err != nil {
			log.Printf("[searxng] Python SearXNG setup failed: %v (%s)", err, firstLine(string(out), 240))
			return ""
		}
	}

	startScript := fmt.Sprintf(
		`SEARXNG_SETTINGS_PATH=%q SEARXNG_BIND_ADDRESS=127.0.0.1 SEARXNG_PORT=8888 nohup %q -m searx.webapp >>/tmp/behemoth-searxng.log 2>&1 &`,
		settingsPath, pyBin,
	)
	_ = exec.CommandContext(ctx, "bash", "-c", startScript).Run()
	return waitSearXNGHealthy(ctx, 25*time.Second)
}

func waitSearXNGHealthy(ctx context.Context, maxWait time.Duration) string {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if localURL := search.DetectLocalSearXNGForce(); localURL != "" {
			return localURL
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(1 * time.Second):
		}
	}
	return search.DetectLocalSearXNGForce()
}
