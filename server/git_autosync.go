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

	"github.com/Autumn-27/behemoth/agent"
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

var (
	maintState   = &maintenanceState{AutoSyncOn: true}
	gitSyncRunMu sync.Mutex
)

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
	for _, envKey := range []string{"BEHEMOTH_WEBHOOK_SECRET", "ARTEX_WEBHOOK_SECRET"} {
		if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
			return v
		}
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
	for _, hdr := range []string{"X-Behemoth-Webhook-Token", "X-Artex-Webhook-Token"} {
		if tok := strings.TrimSpace(r.Header.Get(hdr)); tok != "" {
			if subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1 {
				return true
			}
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
	// Serialize webhook (manual=true) and 60s background ticker (manual=false) so
	// concurrent git fetch/pull calls never collide on .git/refs locks.
	if !gitSyncRunMu.TryLock() {
		return
	}
	defer gitSyncRunMu.Unlock()

	maintState.mu.Lock()
	if maintState.Updating {
		maintState.mu.Unlock()
		return
	}
	maintState.LastChecked = time.Now()
	maintState.mu.Unlock()

	// Automatically migrate legacy pre-rename GitHub remote URLs to the canonical repository.
	if remOut, rerr := exec.CommandContext(ctx, "git", "remote", "get-url", "origin").Output(); rerr == nil {
		rem := strings.TrimSpace(string(remOut))
		if strings.Contains(rem, "Billioncodes001/myartex") || strings.Contains(rem, "Billioncodes001/mybehemoth") {
			_ = exec.CommandContext(ctx, "git", "remote", "set-url", "origin", "https://github.com/Billioncodes001/behemoth.git").Run()
		}
	}

	// Discard incidental lockfile drift produced by prior local `npm` builds before checking tracked files.
	_ = exec.CommandContext(ctx, "git", "checkout", "--", "web/package-lock.json").Run()

	// Check ONLY tracked files (`-uno`) so untracked runtime outputs never block
	// automatic 60-second updates. Runtime-managed paths (agent self-improved
	// `skills/**`, chmod drift on `setup.sh`/`start.sh`, or `server/webui/**`) are
	// auto-stashed & re-applied rather than blocking production live-sync, while
	// genuine code edits (`.go`, `web/src/**`) on a developer checkout still skip safely.
	autoStashRuntimeDirty := false
	if !manual {
		statusOut, err := exec.CommandContext(ctx, "git", "status", "--porcelain", "-uno").Output()
		if err != nil {
			setMaintenanceOutcome("skipped", fmt.Sprintf("git status failed: %v", err))
			return
		}
		if dirty := strings.TrimSpace(string(statusOut)); len(dirty) > 0 {
			onlyRuntimeManaged := true
			for _, line := range strings.Split(dirty, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				fields := strings.Fields(line)
				pathPart := fields[len(fields)-1]
				if strings.HasPrefix(pathPart, "skills/") ||
					strings.HasPrefix(pathPart, "server/webui/") ||
					pathPart == "setup.sh" ||
					pathPart == "start.sh" ||
					pathPart == "web/package-lock.json" {
					continue
				}
				onlyRuntimeManaged = false
				break
			}
			if !onlyRuntimeManaged {
				setMaintenanceOutcome("skipped_dirty_tracked_files", firstLine(dirty, 200))
				return
			}
			autoStashRuntimeDirty = true
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
	webChanged := false
	goBackendChanged := false
	setupChanged := false
	if diffOut, err := exec.CommandContext(ctx, "git", "diff", "--name-only", localSHA+".."+remoteSHA).Output(); err == nil {
		for _, rel := range strings.Split(strings.TrimSpace(string(diffOut)), "\n") {
			rel = strings.TrimSpace(rel)
			if rel == "" {
				continue
			}
			if rel == "web/package.json" || rel == "web/package-lock.json" {
				pkgJSONChanged = true
			}
			if strings.HasPrefix(rel, "web/") {
				webChanged = true
			}
			if rel == "setup.sh" || rel == "start.sh" || strings.HasPrefix(rel, "deploy/") {
				setupChanged = true
			}
			if strings.HasSuffix(rel, ".go") || rel == "go.mod" || rel == "go.sum" || strings.HasPrefix(rel, "db/schema.sql") {
				goBackendChanged = true
			}
			// If an untracked local file exists at an incoming tracked path, back it up so git pull never aborts.
			if _, stErr := os.Stat(rel); stErr == nil {
				if lsErr := exec.CommandContext(ctx, "git", "ls-files", "--error-unmatch", rel).Run(); lsErr != nil {
					_ = os.Rename(rel, rel+".pre-sync.bak")
				}
			}
		}
	} else {
		// Conservative fallback if diff inspection failed.
		goBackendChanged = true
		webChanged = true
	}

	stashedSkills := false
	if manual || autoStashRuntimeDirty {
		// Stash local tracked edits (e.g. agent-updated skills/** on production) so fast-forward succeeds cleanly.
		if preOut, _ := exec.CommandContext(ctx, "git", "status", "--porcelain", "-uno").Output(); len(strings.TrimSpace(string(preOut))) > 0 {
			if exec.CommandContext(ctx, "git", "stash", "push", "--quiet", "-m", "behemoth-autosync-"+time.Now().UTC().Format("20060102T150405Z")).Run() == nil {
				stashedSkills = autoStashRuntimeDirty
			}
		}
	}

	shortRemote := remoteSHA
	if len(shortRemote) > 8 {
		shortRemote = shortRemote[:8]
	}
	log.Printf("[git-sync] New repository update detected on origin/main (%s -> %s, goBackendChanged=%v, webChanged=%v)...",
		localSHA[:minInt(8, len(localSHA))], shortRemote, goBackendChanged, webChanged)
	setMaintenanceUpdating(true, "Pulling latest updates from repository ("+shortRemote+")...", shortRemote)

	if out, err := exec.CommandContext(ctx, "git", "pull", "--ff-only", "origin", "main").CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("git pull failed: %v (%s)", err, firstLine(string(out), 240))
		log.Printf("[git-sync] %s", errMsg)
		setMaintenanceOutcome("pull_failed", errMsg)
		setMaintenanceUpdating(false, "", "")
		return
	}
	_ = os.Chmod("setup.sh", 0o755)
	_ = os.Chmod("start.sh", 0o755)
	if stashedSkills {
		// Best-effort restore of non-conflicting agent skill improvements; if conflicted, reset cleanly to upstream HEAD.
		if exec.CommandContext(ctx, "git", "stash", "apply", "--quiet").Run() != nil {
			_ = exec.CommandContext(ctx, "git", "checkout", "--", ".").Run()
		}
	}

	needNpmInstall := "0"
	if pkgJSONChanged {
		needNpmInstall = "1"
	}

	// ZERO-RESTART HOT-RELOAD PATH: when only Web UI, Skills, Docs, or Scripts changed
	// (no Go backend code modified), rebuild static assets & refresh skills in-place
	// without restarting the server process — running agents never even pause!
	if !goBackendChanged {
		if webChanged {
			setMaintenanceUpdating(true, "Hot-reloading Web UI assets in place ("+shortRemote+")...", shortRemote)
			hotWebCmd := exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf(`
				set -e
				if command -v npm >/dev/null 2>&1 && [ -d web ]; then
					if [ ! -d web/node_modules ] || [ "%s" = "1" ]; then
						(cd web && npm install --no-audit --no-fund)
					fi
					(cd web && npm run build:static && mkdir -p ../server/webui && rm -rf ../server/webui/dist.next && cp -r out ../server/webui/dist.next && rm -rf ../server/webui/dist.prev && ( [ ! -d ../server/webui/dist ] || mv ../server/webui/dist ../server/webui/dist.prev ) && mv ../server/webui/dist.next ../server/webui/dist && rm -rf ../server/webui/dist.prev)
				fi
			`, needNpmInstall))
			if out, err := hotWebCmd.CombinedOutput(); err != nil {
				errMsg := fmt.Sprintf("hot web build failed: %v (%s)", err, firstLine(string(out), 300))
				log.Printf("[git-sync] %s", errMsg)
				setMaintenanceOutcome("build_failed", errMsg)
				setMaintenanceUpdating(false, "", "")
				return
			}
			ClearWebUICache()
		}
		if s != nil {
			s.syncDiscoveredSkillsVisibility()
			s.ensureDefaultWordlists()
			if setupChanged {
				go s.ensureLocalSearXNGService(s.ctx)
			}
		}
		if headOut, herr := exec.CommandContext(ctx, "git", "rev-parse", "--short", "HEAD").Output(); herr == nil {
			maintState.mu.Lock()
			maintState.CurrentSHA = strings.TrimSpace(string(headOut))
			maintState.TargetSHA = ""
			maintState.mu.Unlock()
		}
		setMaintenanceOutcome("up_to_date", "")
		setMaintenanceUpdating(false, "", "")
		log.Printf("[git-sync] Hot-reloaded %s in place with zero process restart — all running agents & services remained uninterrupted.", shortRemote)
		return
	}

	// GO BACKEND BINARY UPDATE PATH: build Web UI only if web/** changed or server/webui/dist is absent,
	// compile the new binary, wait for active agent tool calls to hit a clean step boundary,
	// and trigger a seamless live-update handoff (which auto-resumes all running agents on boot).
	needWebBuild := "0"
	if webChanged {
		needWebBuild = "1"
	} else if _, stErr := os.Stat(filepath.Join("server", "webui", "dist", "index.html")); stErr != nil {
		needWebBuild = "1"
	}

	setMaintenanceUpdating(true, "Building updated server binary ("+shortRemote+")...", shortRemote)
	buildCmd := exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf(`
		set -e
		if [ "%s" = "1" ] && command -v npm >/dev/null 2>&1 && [ -d web ]; then
			if [ ! -d web/node_modules ] || [ "%s" = "1" ]; then
				(cd web && npm install --no-audit --no-fund)
			fi
			(cd web && npm run build:static && rm -rf ../server/webui/dist && mkdir -p ../server/webui && cp -r out ../server/webui/dist)
			if [ -f /etc/nginx/sites-enabled/behemoth.conf ] || [ -f /etc/nginx/sites-enabled/artex.conf ]; then
				# Nginx fronts the embedded Go binary on :8787 directly; reclaim any idle :3000 Node server RAM.
				for pidf in /tmp/behemoth-web.pid /tmp/artex-web.pid; do
					if [ -f "$pidf" ]; then
						kill "$(cat "$pidf")" 2>/dev/null || true
						rm -f "$pidf"
					fi
				done
				if command -v tmux >/dev/null 2>&1; then
					tmux kill-window -t behemoth:frontend 2>/dev/null || true
					tmux kill-window -t artex:frontend 2>/dev/null || true
				fi
			elif pgrep -f "next start" >/dev/null 2>&1; then
				(cd web && npm run build)
			fi
		fi
		# Ensure go:embed all:webui/dist always has a valid directory even on fresh checkouts
		mkdir -p server/webui/dist
		if [ ! -f server/webui/dist/index.html ]; then
			echo "<!doctype html><title>BEHEMOTH</title>" > server/webui/dist/index.html
		fi
		BUILD_VER="$(git describe --tags --abbrev=0 2>/dev/null || echo 2.4.0)"
		BUILD_VER="${BUILD_VER#v}"
		CGO_ENABLED=0 go build -tags embedui -trimpath -ldflags "-s -w -X main.version=${BUILD_VER}" -o behemoth.new ./cmd/behemoth
		mv -f behemoth.new behemoth
		chmod +x behemoth
		# Legacy keep-alive: pre-rename supervisors and Docker entrypoints still exec ./artex.
		# rm+cp (not cp in place) avoids ETXTBSY while the old binary is still running.
		rm -f artex && cp -f behemoth artex 2>/dev/null || true
	`, needWebBuild, needNpmInstall))
	if out, err := buildCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("build failed: %v (%s)", err, firstLine(string(out), 300))
		log.Printf("[git-sync] %s", errMsg)
		setMaintenanceOutcome("build_failed", errMsg)
		setMaintenanceUpdating(false, "", "")
		return
	}

	if activeTools := agent.ActiveToolExecutions(); activeTools > 0 {
		setMaintenanceUpdating(true, fmt.Sprintf("Waiting for %d active agent tool step(s) to finish cleanly before hot-swap (%s)...", activeTools, shortRemote), shortRemote)
		waitForCleanAgentStepBoundary(ctx, 45*time.Second)
	}

	if s != nil {
		s.persistActiveTurnsForLiveUpdate()
	}
	setMaintenanceOutcome("updated_restarting", "")
	setMaintenanceUpdating(true, "Applying live update & seamlessly resuming active agents ("+shortRemote+")...", shortRemote)
	log.Printf("[git-sync] Update %s built successfully. Triggering seamless live-update handoff...", shortRemote)
	time.AfterFunc(800*time.Millisecond, func() {
		requestLiveUpdateRestart()
	})
}

func waitForCleanAgentStepBoundary(ctx context.Context, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if agent.ActiveToolExecutions() == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}
