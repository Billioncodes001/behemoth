package server

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"log"
)

type maintenanceState struct {
	mu           sync.RWMutex
	Updating     bool      `json:"updating"`
	Phase        string    `json:"phase,omitempty"`
	CurrentSHA   string    `json:"current_sha,omitempty"`
	TargetSHA    string    `json:"target_sha,omitempty"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	LastChecked  time.Time `json:"last_checked,omitempty"`
	AutoSyncOn   bool      `json:"auto_sync_enabled"`
}

var maintState = &maintenanceState{AutoSyncOn: true}

func getMaintenanceSnapshot() map[string]any {
	maintState.mu.RLock()
	defer maintState.mu.RUnlock()
	return map[string]any{
		"updating":          maintState.Updating,
		"phase":             maintState.Phase,
		"current_sha":       maintState.CurrentSHA,
		"target_sha":        maintState.TargetSHA,
		"started_at":        maintState.StartedAt,
		"last_checked":      maintState.LastChecked,
		"auto_sync_enabled": maintState.AutoSyncOn,
	}
}

func setMaintenanceUpdating(updating bool, phase, targetSHA string) {
	maintState.mu.Lock()
	defer maintState.mu.Unlock()
	maintState.Updating = updating
	maintState.Phase = phase
	if targetSHA != "" {
		maintState.TargetSHA = targetSHA
	}
	if updating && maintState.StartedAt.IsZero() {
		maintState.StartedAt = time.Now()
	} else if !updating {
		maintState.StartedAt = time.Time{}
	}
}

// GET /api/update/maintenance (Public - exempt from auth so login & active tabs see maintenance status)
func (s *Server) handleMaintenanceStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, getMaintenanceSnapshot())
}

// POST /api/update/webhook & POST /api/update/git-sync — triggers an immediate git check & live update.
func (s *Server) handleTriggerGitSync(w http.ResponseWriter, r *http.Request) {
	go s.checkAndApplyGitUpdate(s.ctx, true)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "Git repository sync check triggered",
	})
}

func (s *Server) startGitAutoSync(ctx context.Context) {
	repoDir, err := os.Getwd()
	if err != nil {
		return
	}
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		return
	}
	if out, err := exec.CommandContext(ctx, "git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		maintState.mu.Lock()
		maintState.CurrentSHA = strings.TrimSpace(string(out))
		maintState.mu.Unlock()
	}

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if s.m != nil && s.m.pg != nil && !s.m.pg.GetBool("git_autosync_enabled", true) {
					continue
				}
				s.checkAndApplyGitUpdate(ctx, false)
			}
		}
	}()
	log.Printf("[git-sync] Automatic Git live-sync watcher active (polling origin/main every 60s)")
}

func (s *Server) checkAndApplyGitUpdate(ctx context.Context, manual bool) {
	maintState.mu.Lock()
	if maintState.Updating {
		maintState.mu.Unlock()
		return
	}
	maintState.LastChecked = time.Now()
	maintState.mu.Unlock()

	// Only auto-pull when the working tree is clean (so local uncommitted dev work is never overwritten)
	if !manual {
		statusOut, err := exec.CommandContext(ctx, "git", "status", "--porcelain").Output()
		if err != nil || len(strings.TrimSpace(string(statusOut))) > 0 {
			return
		}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(fetchCtx, "git", "fetch", "origin", "main", "--tags", "--quiet").Run(); err != nil {
		return
	}

	localOut, err1 := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	remoteOut, err2 := exec.CommandContext(ctx, "git", "rev-parse", "origin/main").Output()
	if err1 != nil || err2 != nil {
		return
	}
	localSHA := strings.TrimSpace(string(localOut))
	remoteSHA := strings.TrimSpace(string(remoteOut))
	if localSHA == "" || remoteSHA == "" || localSHA == remoteSHA {
		return
	}

	shortRemote := remoteSHA
	if len(shortRemote) > 8 {
		shortRemote = shortRemote[:8]
	}
	log.Printf("[git-sync] New repository update detected on origin/main (%s -> %s). Entering maintenance mode and rebuilding...", localSHA[:8], shortRemote)
	setMaintenanceUpdating(true, "Pulling latest updates from repository ("+shortRemote+")...", shortRemote)

	if err := exec.CommandContext(ctx, "git", "pull", "--ff-only", "origin", "main").Run(); err != nil {
		log.Printf("[git-sync] git pull failed: %v", err)
		setMaintenanceUpdating(false, "", "")
		return
	}

	setMaintenanceUpdating(true, "Building updated Web UI & server binary ("+shortRemote+")...", shortRemote)
	buildCmd := exec.CommandContext(ctx, "bash", "-c", `
		set -e
		if command -v npm >/dev/null 2>&1 && [ -d web ]; then
			(cd web && npm run build:static && rm -rf ../server/webui/dist && mkdir -p ../server/webui && cp -r out ../server/webui/dist)
			if [ -f /etc/nginx/sites-enabled/artex.conf ]; then
				# Nginx fronts the embedded Go binary on :8787 directly; reclaim any idle :3000 Node server RAM.
				if [ -f /tmp/artex-web.pid ]; then
					kill "$(cat /tmp/artex-web.pid)" 2>/dev/null || true
					rm -f /tmp/artex-web.pid
				fi
				if command -v tmux >/dev/null 2>&1; then
					tmux kill-window -t artex:frontend 2>/dev/null || true
				fi
			elif pgrep -f "next start" >/dev/null 2>&1; then
				(cd web && npm run build)
			fi
		fi
		BUILD_VER="$(git describe --tags --abbrev=0 2>/dev/null || echo 2.3.0)"
		BUILD_VER="${BUILD_VER#v}"
		CGO_ENABLED=0 go build -tags embedui -trimpath -ldflags "-s -w -X main.version=${BUILD_VER}" -o artex.new ./cmd/artex
		mv -f artex.new artex
		chmod +x artex
	`)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		log.Printf("[git-sync] build failed: %v (%s)", err, string(out))
		setMaintenanceUpdating(false, "", "")
		return
	}

	setMaintenanceUpdating(true, "Restarting ARTEX services to apply update ("+shortRemote+")...", shortRemote)
	log.Printf("[git-sync] Update %s built successfully. Signaling supervisor to restart...", shortRemote)
	time.AfterFunc(1500*time.Millisecond, func() {
		requestRestart()
	})
}
