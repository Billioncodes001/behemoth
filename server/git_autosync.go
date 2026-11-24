package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const webhookMinCooldown = 20 * time.Second

type maintenanceState struct {
	mu              sync.RWMutex
	Updating        bool      `json:"updating"`
	Phase           string    `json:"phase,omitempty"`
	CurrentSHA      string    `json:"current_sha,omitempty"`
	TargetSHA       string    `json:"target_sha,omitempty"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	LastChecked     time.Time `json:"last_checked,omitempty"`
	LastWebhookCall time.Time `json:"-"`
	LastResult      string    `json:"last_result,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	AutoSyncOn      bool      `json:"auto_sync_enabled"`
}

var maintState = &maintenanceState{AutoSyncOn: true}

func getMaintenanceSnapshot() map[string]any {
	maintState.mu.RLock()
	defer maintState.mu.RUnlock()
	return map[string]any{
		"version":           BuildVersion,
		"updating":          maintState.Updating,
		"phase":             maintState.Phase,
		"current_sha":       maintState.CurrentSHA,
		"target_sha":        maintState.TargetSHA,
		"started_at":        maintState.StartedAt,
		"last_checked":      maintState.LastChecked,
		"last_result":       maintState.LastResult,
		"last_error":        maintState.LastError,
		"auto_sync_enabled": maintState.AutoSyncOn,
	}
}

func setMaintenanceOutcome(result, errMsg string) {
	maintState.mu.Lock()
	defer maintState.mu.Unlock()
	maintState.LastResult = result
	maintState.LastError = errMsg
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

func (s *Server) configuredWebhookSecret() string {
	if v := strings.TrimSpace(os.Getenv("BEHEMOTH_WEBHOOK_SECRET")); v != "" {
		return v
	}
	if s != nil && s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting("webhook_secret"); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func verifyGitWebhookAuth(r *http.Request, secret string, body []byte) bool {
	if secret == "" {
		return true
	}
	if tok := strings.TrimSpace(r.Header.Get("X-Behemoth-Webhook-Token")); tok != "" {
		if subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1 {
			return true
		}
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(auth, "Bearer ") {
		tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1 {
			return true
		}
	}
	if sig := strings.TrimSpace(r.Header.Get("X-Hub-Signature-256")); strings.HasPrefix(sig, "sha256=") {
		gotHex := strings.TrimPrefix(sig, "sha256=")
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		wantHex := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(gotHex)), []byte(wantHex)) == 1 {
			return true
		}
	}
	return false
}

// POST /api/update/webhook & POST /api/update/git-sync — triggers an immediate git check & live update.
func (s *Server) handleTriggerGitSync(w http.ResponseWriter, r *http.Request) {
	isPublicWebhook := r.URL != nil && r.URL.Path == "/api/update/webhook"
	if isPublicWebhook {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "Webhook payload too large")
			return
		}
		if secret := s.configuredWebhookSecret(); secret != "" && !verifyGitWebhookAuth(r, secret, body) {
			writeErr(w, http.StatusUnauthorized, "Invalid or missing webhook signature/token")
			return
		}
		now := time.Now()
		maintState.mu.Lock()
		if !maintState.LastWebhookCall.IsZero() && now.Sub(maintState.LastWebhookCall) < webhookMinCooldown {
			retry := int((webhookMinCooldown - now.Sub(maintState.LastWebhookCall)).Seconds())
			if retry < 1 {
				retry = 1
			}
			maintState.mu.Unlock()
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeErr(w, http.StatusTooManyRequests, "Webhook sync rate-limited; retry shortly")
			return
		}
		maintState.LastWebhookCall = now
		maintState.mu.Unlock()
	}

	if s != nil && s.ctx != nil {
		go s.checkAndApplyGitUpdate(s.ctx, true)
	}
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
		// Perform one initial check shortly after boot so restarts don't wait a full minute.
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
			if s.m == nil || s.m.pg == nil || s.m.pg.GetBool("git_autosync_enabled", true) {
				s.checkAndApplyGitUpdate(ctx, false)
			}
		}
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

	// Discard incidental lockfile drift produced by prior local `npm` builds before checking tracked files.
	_ = exec.CommandContext(ctx, "git", "checkout", "--", "web/package-lock.json").Run()

	// Check ONLY tracked files (`-uno`) so untracked runtime outputs (reports, custom skills,
	// temporary logs) never block automatic 60-second updates on production.
	if !manual {
		statusOut, err := exec.CommandContext(ctx, "git", "status", "--porcelain", "-uno").Output()
		if err != nil {
			setMaintenanceOutcome("skipped", fmt.Sprintf("git status failed: %v", err))
			return
		}
		if dirty := strings.TrimSpace(string(statusOut)); len(dirty) > 0 {
			setMaintenanceOutcome("skipped_dirty_tracked_files", firstLine(dirty, 200))
			return
		}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(fetchCtx, "git", "fetch", "origin", "main", "--tags", "--force", "--quiet").CombinedOutput(); err != nil {
		setMaintenanceOutcome("fetch_failed", fmt.Sprintf("%v (%s)", err, firstLine(string(out), 200)))
		return
	}

	localOut, err1 := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	remoteOut, err2 := exec.CommandContext(ctx, "git", "rev-parse", "origin/main").Output()
	if err1 != nil || err2 != nil {
		setMaintenanceOutcome("rev_parse_failed", "unable to resolve HEAD or origin/main")
		return
	}
	localSHA := strings.TrimSpace(string(localOut))
	remoteSHA := strings.TrimSpace(string(remoteOut))
	if localSHA == "" || remoteSHA == "" || localSHA == remoteSHA {
		setMaintenanceOutcome("up_to_date", "")
		return
	}

	pkgJSONChanged := false
	if diffOut, err := exec.CommandContext(ctx, "git", "diff", "--name-only", localSHA+".."+remoteSHA).Output(); err == nil {
		for _, rel := range strings.Split(strings.TrimSpace(string(diffOut)), "\n") {
			rel = strings.TrimSpace(rel)
			if rel == "" {
				continue
			}
			if rel == "web/package.json" || rel == "web/package-lock.json" {
				pkgJSONChanged = true
			}
			// If an untracked local file exists at an incoming tracked path, back it up so git pull never aborts.
			if _, stErr := os.Stat(rel); stErr == nil {
				if lsErr := exec.CommandContext(ctx, "git", "ls-files", "--error-unmatch", rel).Run(); lsErr != nil {
					_ = os.Rename(rel, rel+".pre-sync.bak")
				}
			}
		}
	}

	if manual {
		// Stash any local tracked edits during an explicit webhook/manual sync so fast-forward succeeds cleanly.
		_ = exec.CommandContext(ctx, "git", "stash", "push", "--quiet", "-m", "behemoth-manual-sync-"+time.Now().UTC().Format("20060102T150405Z")).Run()
	}

	shortRemote := remoteSHA
	if len(shortRemote) > 8 {
		shortRemote = shortRemote[:8]
	}
	log.Printf("[git-sync] New repository update detected on origin/main (%s -> %s). Entering maintenance mode and rebuilding...", localSHA[:minInt(8, len(localSHA))], shortRemote)
	setMaintenanceUpdating(true, "Pulling latest updates from repository ("+shortRemote+")...", shortRemote)

	if out, err := exec.CommandContext(ctx, "git", "pull", "--ff-only", "origin", "main").CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("git pull failed: %v (%s)", err, firstLine(string(out), 240))
		log.Printf("[git-sync] %s", errMsg)
		setMaintenanceOutcome("pull_failed", errMsg)
		setMaintenanceUpdating(false, "", "")
		return
	}

	setMaintenanceUpdating(true, "Building updated Web UI & server binary ("+shortRemote+")...", shortRemote)
	needNpmInstall := "0"
	if pkgJSONChanged {
		needNpmInstall = "1"
	}
	buildCmd := exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf(`
		set -e
		if command -v npm >/dev/null 2>&1 && [ -d web ]; then
			if [ ! -d web/node_modules ] || [ "%s" = "1" ]; then
				(cd web && npm install --no-audit --no-fund)
			fi
			(cd web && npm run build:static && rm -rf ../server/webui/dist && mkdir -p ../server/webui && cp -r out ../server/webui/dist)
			if [ -f /etc/nginx/sites-enabled/behemoth.conf ]; then
				# Nginx fronts the embedded Go binary on :8787 directly; reclaim any idle :3000 Node server RAM.
				if [ -f /tmp/behemoth-web.pid ]; then
					kill "$(cat /tmp/behemoth-web.pid)" 2>/dev/null || true
					rm -f /tmp/behemoth-web.pid
				fi
				if command -v tmux >/dev/null 2>&1; then
					tmux kill-window -t behemoth:frontend 2>/dev/null || true
				fi
			elif pgrep -f "next start" >/dev/null 2>&1; then
				(cd web && npm run build)
			fi
		fi
		BUILD_VER="$(git describe --tags --abbrev=0 2>/dev/null || echo 2.4.0)"
		BUILD_VER="${BUILD_VER#v}"
		CGO_ENABLED=0 go build -tags embedui -trimpath -ldflags "-s -w -X main.version=${BUILD_VER}" -o behemoth.new ./cmd/behemoth
		mv -f behemoth.new behemoth
		chmod +x behemoth
		# Legacy keep-alive: pre-rename supervisors and Docker entrypoints still exec ./artex.
		# rm+cp (not cp in place) avoids ETXTBSY while the old binary is still running.
		rm -f artex && cp -f behemoth artex 2>/dev/null || true
	`, needNpmInstall))
	if out, err := buildCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("build failed: %v (%s)", err, firstLine(string(out), 300))
		log.Printf("[git-sync] %s", errMsg)
		setMaintenanceOutcome("build_failed", errMsg)
		setMaintenanceUpdating(false, "", "")
		return
	}

	setMaintenanceOutcome("updated_restarting", "")
	setMaintenanceUpdating(true, "Restarting BEHEMOTH services to apply update ("+shortRemote+")...", shortRemote)
	log.Printf("[git-sync] Update %s built successfully. Signaling supervisor to restart...", shortRemote)
	time.AfterFunc(1500*time.Millisecond, func() {
		requestRestart()
	})
}
