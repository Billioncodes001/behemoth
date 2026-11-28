package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/behemoth/db"
)

const (
	colabRepoURL          = "https://github.com/alesha-pro/tools.git"
	colabDefaultPort      = 18100
	colabDefaultTier      = "3.05"
	colabDefaultCtx       = 131072
	colabDefaultSession   = "glm53"
	colabMaxLogEntries    = 80
	colabKeyringBackend   = "keyrings.alt.file.PlaintextKeyring"
	settingColabG4Profile = "colab_g4_llm_profile_id"
)

var (
	reGoogleOAuthURL = regexp.MustCompile(`https://accounts\.google\.com/o/oauth2/[^\s"'<>]+`)
	reEmailAddress   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reComputeBalance = regexp.MustCompile(`(?i)current\s+balance:\s*([0-9]+(?:\.[0-9]+)?)\s*compute\s+units`)
	reG4BusyRetry    = regexp.MustCompile(`(?i)g4\s+busy\s*\(503\).*retry\s*#?(\d+)`)
	reANSI           = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
)

type ColabLogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"` // info | ok | warn | error
	Message   string `json:"message"`
}

type ColabG4Status struct {
	CLIInstalled            bool            `json:"cli_installed"`
	CLIPath                 string          `json:"cli_path,omitempty"`
	ScriptsInstalled        bool            `json:"scripts_installed"`
	Authenticated           bool            `json:"authenticated"`
	GoogleEmail             string          `json:"google_email,omitempty"`
	ComputeUnits            float64         `json:"compute_units"`
	HasEligibleSubscription bool            `json:"has_eligible_subscription"`
	SubscriptionNote        string          `json:"subscription_note,omitempty"`
	UsageSummary            string          `json:"usage_summary,omitempty"`
	SessionsSummary         string          `json:"sessions_summary,omitempty"`
	AuthInProgress   bool            `json:"auth_in_progress"`
	AuthURL          string          `json:"auth_url,omitempty"`
	AuthError        string          `json:"auth_error,omitempty"`
	State            string          `json:"state"` // idle | installing | starting | running | stopping | error
	Phase            string          `json:"phase"`
	Tier             string          `json:"tier"`
	CtxSize          int             `json:"ctx_size"`
	Port             int             `json:"port"`
	EndpointURL      string          `json:"endpoint_url"`
	ModelName        string          `json:"model_name"`
	TunnelHealthy    bool            `json:"tunnel_healthy"`
	ProfileID        int64           `json:"profile_id,omitempty"`
	LastError        string          `json:"last_error,omitempty"`
	Logs             []ColabLogEntry `json:"logs"`
}

type colabAuthSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	cancel context.CancelFunc
	doneCh chan error
	urlCh  chan string
}

type colabG4Runtime struct {
	mu           sync.Mutex
	state        string
	phase        string
	tier         string
	ctxSize      int
	port         int
	lastError    string
	authURL      string
	authError    string
	googleEmail  string
	computeUnits float64
	hasCUData    bool
	usageSummary string
	sessionsText string
	authDoneAt   time.Time
	activeAuth   *colabAuthSession
	startCancel  context.CancelFunc
	logs         []ColabLogEntry
}

var colabRT = &colabG4Runtime{
	state:   "idle",
	phase:   "Idle",
	tier:    colabDefaultTier,
	ctxSize: colabDefaultCtx,
	port:    colabDefaultPort,
}

func (s *Server) colabBaseDir() string {
	base := s.dataDir
	if base == "" && s.m != nil {
		base = s.m.dir
	}
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "colab-g4")
}

func (s *Server) colabVenvDir() string {
	return filepath.Join(s.colabBaseDir(), "venv")
}

func (s *Server) colabRepoDir() string {
	return filepath.Join(s.colabBaseDir(), "repo")
}

func (s *Server) colabScriptsDir() string {
	return filepath.Join(s.colabRepoDir(), "colab-g4-glm53")
}

func (s *Server) findColabCLI() string {
	candidates := []string{
		filepath.Join(s.colabVenvDir(), "bin", "colab"),
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".local", "bin", "colab"))
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	if p, err := exec.LookPath("colab"); err == nil {
		return p
	}
	return ""
}

func (s *Server) colabScriptsReady() bool {
	st, err := os.Stat(filepath.Join(s.colabScriptsDir(), "start.sh"))
	return err == nil && !st.IsDir()
}

func (s *Server) colabCmdEnv(cliPath string) []string {
	env := os.Environ()
	extras := map[string]string{
		"PYTHONUNBUFFERED":       "1",
		"BROWSER":                "false",
		"NO_COLOR":               "1",
		"PYTHON_KEYRING_BACKEND": colabKeyringBackend,
	}
	if cliPath != "" {
		extras["COLAB_BIN"] = cliPath
		binDir := filepath.Dir(cliPath)
		extras["PATH"] = binDir + ":" + os.Getenv("PATH")
	}
	out := make([]string, 0, len(env)+len(extras))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if _, override := extras[k]; override {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range extras {
		out = append(out, k+"="+v)
	}
	return out
}

func appendColabLog(level, msg string) {
	clean := strings.TrimSpace(reANSI.ReplaceAllString(msg, ""))
	if clean == "" {
		return
	}
	entry := ColabLogEntry{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     level,
		Message:   clean,
	}
	colabRT.mu.Lock()
	colabRT.logs = append(colabRT.logs, entry)
	if len(colabRT.logs) > colabMaxLogEntries {
		colabRT.logs = colabRT.logs[len(colabRT.logs)-colabMaxLogEntries:]
	}
	colabRT.mu.Unlock()
}

func checkColabTunnelHealth(port int) bool {
	if port <= 0 {
		port = colabDefaultPort
	}
	cl := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	resp, err := cl.Get(fmt.Sprintf("http://127.0.0.1:%d/v1/models", port))
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// extractOAuthCodeFromInput accepts either a raw Google authorization code OR a
// full redirect URL containing `?code=...` so non-technical users can paste either.
func extractOAuthCodeFromInput(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if u, err := url.Parse(s); err == nil {
			if code := strings.TrimSpace(u.Query().Get("code")); code != "" {
				return code
			}
		}
	}
	return s
}

func (s *Server) probeColabAuthNonInteractive(ctx context.Context, cliPath string) (email, usage, sessions string, authed bool) {
	if cliPath == "" {
		return "", "", "", false
	}
	runQuick := func(args ...string) (string, error) {
		qCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
		defer cancel()
		cmd := exec.CommandContext(qCtx, cliPath, args...)
		cmd.Env = s.colabCmdEnv(cliPath)
		cmd.Stdin = strings.NewReader("") // EOF immediately if CLI tries to prompt for OAuth
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(reANSI.ReplaceAllString(string(out), "")), err
	}

	whoOut, whoErr := runQuick("whoami")
	if whoErr == nil && !reGoogleOAuthURL.MatchString(whoOut) {
		if m := reEmailAddress.FindString(whoOut); m != "" {
			email = m
			authed = true
		} else if whoOut != "" && !strings.Contains(strings.ToLower(whoOut), "error") {
			authed = true
		}
	}
	if !authed {
		return "", "", "", false
	}
	if uOut, uErr := runQuick("usage"); uErr == nil && !reGoogleOAuthURL.MatchString(uOut) {
		usage = firstLinesSummary(uOut, 4)
	}
	if sOut, sErr := runQuick("sessions"); sErr == nil && !reGoogleOAuthURL.MatchString(sOut) {
		sessions = firstLinesSummary(sOut, 4)
	}
	return email, usage, sessions, true
}

func firstLinesSummary(s string, maxLines int) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		t := strings.TrimSpace(ln)
		if t != "" {
			out = append(out, t)
			if len(out) >= maxLines {
				break
			}
		}
	}
	return strings.Join(out, " · ")
}

func parseColabComputeUnits(usageText string) (float64, bool) {
	if m := reComputeBalance.FindStringSubmatch(usageText); len(m) >= 2 {
		var val float64
		if _, err := fmt.Sscanf(m[1], "%f", &val); err == nil {
			return val, true
		}
	}
	return 0, false
}

// startColabAutoSetup ensures google-colab-cli and the colab-g4-glm53 scripts are
// provisioned automatically in the background on server startup so users never need
// a separate manual CLI install button in the Web UI.
func (s *Server) startColabAutoSetup() {
	if s == nil || s.ctx == nil {
		return
	}
	go func() {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(8 * time.Second):
		}
		if s.findColabCLI() != "" && s.colabScriptsReady() {
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
		defer cancel()
		if _, err := s.ensureColabDependencies(ctx); err != nil {
			log.Printf("[colab-g4] background auto-setup deferred: %v", err)
		}
	}()
}

func (s *Server) colabStatusSnapshot(ctx context.Context, probeRemote bool) ColabG4Status {
	cliPath := s.findColabCLI()
	scriptsOK := s.colabScriptsReady()

	colabRT.mu.Lock()
	tier := colabRT.tier
	ctxSize := colabRT.ctxSize
	port := colabRT.port
	state := colabRT.state
	phase := colabRT.phase
	lastErr := colabRT.lastError
	authInProg := colabRT.activeAuth != nil
	authURL := colabRT.authURL
	authErr := colabRT.authError
	email := colabRT.googleEmail
	computeUnits := colabRT.computeUnits
	hasCUData := colabRT.hasCUData
	usage := colabRT.usageSummary
	sessions := colabRT.sessionsText
	logsCopy := append([]ColabLogEntry(nil), colabRT.logs...)
	colabRT.mu.Unlock()

	if tier == "" {
		tier = colabDefaultTier
	}
	if ctxSize <= 0 {
		ctxSize = colabDefaultCtx
	}
	if port <= 0 {
		port = colabDefaultPort
	}

	authed := email != ""
	if probeRemote && cliPath != "" && !authInProg {
		if em, us, se, ok := s.probeColabAuthNonInteractive(ctx, cliPath); ok {
			authed = true
			email, usage, sessions = em, us, se
			cu, cuOK := parseColabComputeUnits(us)
			computeUnits, hasCUData = cu, cuOK
			colabRT.mu.Lock()
			colabRT.googleEmail = em
			colabRT.computeUnits = cu
			colabRT.hasCUData = cuOK
			colabRT.usageSummary = us
			colabRT.sessionsText = se
			colabRT.mu.Unlock()
		} else {
			authed = false
			email, usage, sessions = "", "", ""
			computeUnits, hasCUData = 0, false
			colabRT.mu.Lock()
			colabRT.googleEmail = ""
			colabRT.computeUnits = 0
			colabRT.hasCUData = false
			colabRT.usageSummary = ""
			colabRT.sessionsText = ""
			colabRT.mu.Unlock()
		}
	}

	hasEligibleSub := false
	subNote := ""
	if authed {
		if hasCUData {
			if computeUnits >= 10.0 {
				hasEligibleSub = true
				subNote = fmt.Sprintf("%.2f Compute Units available (~%.1f hrs on Colab G4)", computeUnits, computeUnits/10.05)
			} else {
				hasEligibleSub = false
				subNote = fmt.Sprintf("Only %.2f Compute Units available. A Google AI Pro / Ultra or Colab Compute Units subscription (~10.05 CU/hr) is required to run Colab G4.", computeUnits)
			}
		} else {
			// Usage line unavailable transiently: allow user to try while noting status
			hasEligibleSub = true
			subNote = "Signed in (Compute Units balance will refresh automatically)."
		}
	}

	healthy := checkColabTunnelHealth(port)
	if healthy && state != "stopping" {
		state = "running"
		phase = "Colab G4 tunnel healthy & serving GLM-5.3-Flash"
	} else if !healthy && state == "running" {
		state = "idle"
		phase = "Tunnel offline (click Reconnect or Start)"
	}

	var profID int64
	if s.m != nil && s.m.pg != nil {
		if raw, ok, _ := s.m.pg.GetSetting(settingColabG4Profile); ok && strings.TrimSpace(raw) != "" {
			_, _ = fmt.Sscanf(strings.TrimSpace(raw), "%d", &profID)
		}
	}

	return ColabG4Status{
		CLIInstalled:            cliPath != "",
		CLIPath:                 cliPath,
		ScriptsInstalled:        scriptsOK,
		Authenticated:           authed,
		GoogleEmail:             email,
		ComputeUnits:            computeUnits,
		HasEligibleSubscription: hasEligibleSub,
		SubscriptionNote:        subNote,
		UsageSummary:            usage,
		SessionsSummary:         sessions,
		AuthInProgress:   authInProg,
		AuthURL:          authURL,
		AuthError:        authErr,
		State:            state,
		Phase:            phase,
		Tier:             tier,
		CtxSize:          ctxSize,
		Port:             port,
		EndpointURL:      fmt.Sprintf("http://127.0.0.1:%d/v1", port),
		ModelName:        fmt.Sprintf("glm-5.3-flash-uncensored-%sbpw", tier),
		TunnelHealthy:    healthy,
		ProfileID:        profID,
		LastError:        lastErr,
		Logs:             logsCopy,
	}
}

// ensureColabDependencies installs google-colab-cli (+ keyrings.alt for headless
// Linux credential persistence) in an isolated venv under <dataDir>/colab-g4/venv
// and clones/updates alesha-pro/tools/colab-g4-glm53.
func (s *Server) ensureColabDependencies(ctx context.Context) (string, error) {
	baseDir := s.colabBaseDir()
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return "", err
	}

	cliPath := s.findColabCLI()
	if cliPath == "" {
		appendColabLog("info", "Installing google-colab-cli into isolated Python environment...")
		pyBin := s.pythonInterpreter()
		if pyBin == "" {
			pyBin = "python3"
		}
		venvDir := s.colabVenvDir()
		if _, err := os.Stat(filepath.Join(venvDir, "bin", "pip")); err != nil {
			mkCmd := exec.CommandContext(ctx, pyBin, "-m", "venv", venvDir)
			if out, err := mkCmd.CombinedOutput(); err != nil {
				return "", fmt.Errorf("create venv failed: %v (%s)", err, firstLine(string(out), 200))
			}
		}
		pipBin := filepath.Join(venvDir, "bin", "pip")
		instCmd := exec.CommandContext(ctx, pipBin, "install", "--upgrade", "google-colab-cli", "keyrings.alt")
		instCmd.Env = s.colabCmdEnv("")
		if out, err := instCmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("install google-colab-cli failed: %v (%s)", err, firstLine(string(out), 240))
		}
		cliPath = s.findColabCLI()
		if cliPath == "" {
			return "", fmt.Errorf("google-colab-cli installed but `colab` binary was not found")
		}
		appendColabLog("ok", "Installed google-colab-cli at "+cliPath)
	}

	repoDir := s.colabRepoDir()
	if !s.colabScriptsReady() {
		appendColabLog("info", "Fetching alesha-pro/tools (colab-g4-glm53 launcher scripts)...")
		_ = os.RemoveAll(repoDir)
		gitCmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", colabRepoURL, repoDir)
		if out, err := gitCmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("git clone colab-g4-glm53 failed: %v (%s)", err, firstLine(string(out), 200))
		}
	} else {
		pullCmd := exec.CommandContext(ctx, "git", "-C", repoDir, "pull", "--ff-only")
		_, _ = pullCmd.CombinedOutput()
	}

	for _, name := range []string{"start.sh", "stop.sh", "tunnel.sh"} {
		_ = os.Chmod(filepath.Join(s.colabScriptsDir(), name), 0o755)
	}
	appendColabLog("ok", "Colab G4 launcher scripts ready")
	return cliPath, nil
}

// upsertColabLLMProfile creates or updates the BEHEMOTH LLM profile pointing at
// the running local Colab G4 tunnel (http://127.0.0.1:<port>/v1) and optionally
// activates it immediately.
func (s *Server) upsertColabLLMProfile(tier string, ctxSize, port int, activate bool) (int64, error) {
	if s.m == nil || s.m.pg == nil {
		return 0, fmt.Errorf("database unavailable")
	}
	modelName := fmt.Sprintf("glm-5.3-flash-uncensored-%sbpw", tier)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/v1", port)
	profName := fmt.Sprintf("Colab G4 · GLM-5.3-Flash (%s bpw)", tier)
	cwK := ctxSize / 1024
	if cwK <= 0 {
		cwK = 131
	}

	var existingID int64
	if raw, ok, _ := s.m.pg.GetSetting(settingColabG4Profile); ok && strings.TrimSpace(raw) != "" {
		_, _ = fmt.Sscanf(strings.TrimSpace(raw), "%d", &existingID)
		if existingID > 0 {
			if p, err := s.m.pg.ProfileByID(existingID); err != nil || p == nil {
				existingID = 0
			}
		}
	}

	p := &db.LLMProfile{
		ID:             existingID,
		Name:           profName,
		Format:         "openai",
		BaseURL:        baseURL,
		Model:          modelName,
		APIKey:         "sk-local",
		ContextWindowK: cwK,
		MaxTokens:      8192,
		Streaming:      true,
		Priority:       100,
	}
	id, err := s.m.pg.SaveProfile(p)
	if err != nil {
		return 0, err
	}
	_ = s.m.pg.SetSetting(settingColabG4Profile, fmt.Sprintf("%d", id))
	if activate {
		if err := s.m.pg.SetActiveProfile(id); err != nil {
			return id, err
		}
		s.invalidateProfileAgents()
		s.reapplyActiveProfile()
	}
	return id, nil
}

// ---------- HTTP Handlers (/api/llm/colab-g4/*) ----------

func (s *Server) registerColabG4Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/llm/colab-g4/status", s.handleColabG4Status)
	mux.HandleFunc("POST /api/llm/colab-g4/setup", s.handleColabG4Setup)
	mux.HandleFunc("POST /api/llm/colab-g4/auth/start", s.handleColabG4AuthStart)
	mux.HandleFunc("POST /api/llm/colab-g4/auth/complete", s.handleColabG4AuthComplete)
	mux.HandleFunc("POST /api/llm/colab-g4/auth/logout", s.handleColabG4AuthLogout)
	mux.HandleFunc("POST /api/llm/colab-g4/start", s.handleColabG4Start)
	mux.HandleFunc("POST /api/llm/colab-g4/stop", s.handleColabG4Stop)
	mux.HandleFunc("POST /api/llm/colab-g4/reconnect", s.handleColabG4Reconnect)
}

func (s *Server) handleColabG4Status(w http.ResponseWriter, r *http.Request) {
	probe := r.URL.Query().Get("probe") == "1"
	writeJSON(w, http.StatusOK, s.colabStatusSnapshot(r.Context(), probe))
}

func (s *Server) handleColabG4Setup(w http.ResponseWriter, r *http.Request) {
	colabRT.mu.Lock()
	if colabRT.state == "installing" || colabRT.state == "starting" {
		colabRT.mu.Unlock()
		writeErr(w, http.StatusConflict, "Colab G4 setup or startup is already in progress")
		return
	}
	colabRT.state = "installing"
	colabRT.phase = "Installing google-colab-cli & launcher scripts..."
	colabRT.lastError = ""
	colabRT.mu.Unlock()

	setupCtx, cancel := context.WithTimeout(s.ctx, 4*time.Minute)
	defer cancel()
	_, err := s.ensureColabDependencies(setupCtx)

	colabRT.mu.Lock()
	if err != nil {
		colabRT.state = "error"
		colabRT.phase = "Setup failed"
		colabRT.lastError = err.Error()
	} else {
		colabRT.state = "idle"
		colabRT.phase = "Dependencies installed — Sign in with Google to continue"
		colabRT.lastError = ""
	}
	colabRT.mu.Unlock()

	if err != nil {
		appendColabLog("error", err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.colabStatusSnapshot(r.Context(), true))
}

func (s *Server) handleColabG4AuthStart(w http.ResponseWriter, r *http.Request) {
	setupCtx, setupCancel := context.WithTimeout(s.ctx, 4*time.Minute)
	cliPath, err := s.ensureColabDependencies(setupCtx)
	setupCancel()
	if err != nil {
		appendColabLog("error", "Auto-setup failed before Google Sign-In: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// If already signed in, return immediately without spawning a new OAuth flow.
	if em, us, se, ok := s.probeColabAuthNonInteractive(r.Context(), cliPath); ok {
		colabRT.mu.Lock()
		colabRT.googleEmail = em
		colabRT.usageSummary = us
		colabRT.sessionsText = se
		colabRT.authURL = ""
		colabRT.authError = ""
		colabRT.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"already_authenticated": true,
			"status":                s.colabStatusSnapshot(r.Context(), false),
		})
		return
	}

	// Cancel any stale in-flight auth session.
	colabRT.mu.Lock()
	if colabRT.activeAuth != nil {
		colabRT.activeAuth.cancel()
		colabRT.activeAuth = nil
	}
	colabRT.authURL = ""
	colabRT.authError = ""
	colabRT.mu.Unlock()

	authCtx, cancel := context.WithTimeout(s.ctx, 10*time.Minute)
	cmd := exec.CommandContext(authCtx, cliPath, "whoami")
	cmd.Env = s.colabCmdEnv(cliPath)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		writeErr(w, http.StatusInternalServerError, "failed to open stdin pipe: "+err.Error())
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		writeErr(w, http.StatusInternalServerError, "failed to open stdout pipe: "+err.Error())
		return
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		cancel()
		writeErr(w, http.StatusInternalServerError, "failed to start Google Sign-In: "+err.Error())
		return
	}

	sess := &colabAuthSession{
		cmd:    cmd,
		stdin:  stdinPipe,
		cancel: cancel,
		doneCh: make(chan error, 1),
		urlCh:  make(chan string, 1),
	}
	colabRT.mu.Lock()
	colabRT.activeAuth = sess
	colabRT.mu.Unlock()
	appendColabLog("info", "Initiated Google Sign-In flow via google-colab-cli...")

	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		scanner.Buffer(make([]byte, 0, 64*1024), 512*1024)
		sentURL := false
		for scanner.Scan() {
			line := reANSI.ReplaceAllString(scanner.Text(), "")
			if !sentURL {
				if u := reGoogleOAuthURL.FindString(line); u != "" {
					sentURL = true
					colabRT.mu.Lock()
					colabRT.authURL = u
					colabRT.mu.Unlock()
					select {
					case sess.urlCh <- u:
					default:
					}
					appendColabLog("info", "Google Sign-In link ready — approve access in your browser and paste the authorization code.")
				}
			}
		}
		waitErr := cmd.Wait()
		sess.doneCh <- waitErr
		colabRT.mu.Lock()
		if colabRT.activeAuth == sess {
			colabRT.activeAuth = nil
			if waitErr != nil && colabRT.googleEmail == "" {
				colabRT.authError = firstLine(waitErr.Error(), 180)
			}
		}
		colabRT.mu.Unlock()
	}()

	select {
	case oauthURL := <-sess.urlCh:
		writeJSON(w, http.StatusOK, map[string]any{
			"auth_url": oauthURL,
			"status":   s.colabStatusSnapshot(r.Context(), false),
		})
	case waitErr := <-sess.doneCh:
		if waitErr == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"already_authenticated": true,
				"status":                s.colabStatusSnapshot(r.Context(), true),
			})
			return
		}
		writeErr(w, http.StatusInternalServerError, "Google Sign-In exited before generating OAuth URL: "+waitErr.Error())
	case <-time.After(15 * time.Second):
		writeErr(w, http.StatusGatewayTimeout, "Timed out waiting for google-colab-cli to emit Google Sign-In URL")
	}
}

func (s *Server) handleColabG4AuthComplete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	code := extractOAuthCodeFromInput(body.Code)
	if code == "" {
		writeErr(w, http.StatusBadRequest, "Google authorization code is required")
		return
	}

	colabRT.mu.Lock()
	sess := colabRT.activeAuth
	colabRT.mu.Unlock()
	if sess == nil {
		writeErr(w, http.StatusConflict, "No active Google Sign-In session — click Sign in with Google first")
		return
	}

	if _, err := io.WriteString(sess.stdin, code+"\n"); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to deliver authorization code: "+err.Error())
		return
	}
	_ = sess.stdin.Close()

	select {
	case err := <-sess.doneCh:
		if err != nil {
			appendColabLog("error", "Google Sign-In code rejected or failed: "+err.Error())
			writeErr(w, http.StatusBadRequest, "Google Sign-In failed: "+err.Error())
			return
		}
	case <-time.After(20 * time.Second):
		writeErr(w, http.StatusGatewayTimeout, "Timed out exchanging Google authorization code")
		return
	}

	colabRT.mu.Lock()
	colabRT.authURL = ""
	colabRT.authError = ""
	colabRT.authDoneAt = time.Now()
	colabRT.mu.Unlock()

	st := s.colabStatusSnapshot(r.Context(), true)
	if !st.Authenticated {
		writeErr(w, http.StatusBadRequest, "Authorization finished, but Colab credentials could not be verified — please try signing in again")
		return
	}
	appendColabLog("ok", "Signed in to Google Colab as "+st.GoogleEmail)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleColabG4AuthLogout(w http.ResponseWriter, r *http.Request) {
	colabRT.mu.Lock()
	if colabRT.activeAuth != nil {
		colabRT.activeAuth.cancel()
		colabRT.activeAuth = nil
	}
	colabRT.authURL = ""
	colabRT.authError = ""
	colabRT.googleEmail = ""
	colabRT.usageSummary = ""
	colabRT.sessionsText = ""
	colabRT.mu.Unlock()

	if cliPath := s.findColabCLI(); cliPath != "" {
		cmd := exec.CommandContext(r.Context(), cliPath, "logout")
		cmd.Env = s.colabCmdEnv(cliPath)
		_, _ = cmd.CombinedOutput()
	}
	appendColabLog("info", "Signed out of Google Colab")
	writeJSON(w, http.StatusOK, s.colabStatusSnapshot(r.Context(), false))
}

func (s *Server) handleColabG4Start(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tier         string `json:"tier"`
		CtxSize      int    `json:"ctx_size"`
		Port         int    `json:"port"`
		AutoActivate *bool  `json:"auto_activate"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	tier := strings.TrimSpace(body.Tier)
	if tier != "2.51" && tier != "3.05" && tier != "4.05" {
		tier = colabDefaultTier
	}
	ctxSize := body.CtxSize
	if ctxSize != 131072 && ctxSize != 262144 {
		ctxSize = colabDefaultCtx
	}
	port := body.Port
	if port < 1024 || port > 65535 {
		port = colabDefaultPort
	}
	autoActivate := true
	if body.AutoActivate != nil {
		autoActivate = *body.AutoActivate
	}

	cliPath := s.findColabCLI()
	if cliPath == "" || !s.colabScriptsReady() {
		writeErr(w, http.StatusPreconditionFailed, "Colab CLI or launcher scripts not installed yet — click Setup & Sign in with Google first")
		return
	}

	colabRT.mu.Lock()
	if colabRT.state == "starting" || colabRT.state == "installing" {
		colabRT.mu.Unlock()
		writeErr(w, http.StatusConflict, "Colab G4 launch is already in progress")
		return
	}
	runCtx, cancel := context.WithTimeout(s.ctx, 30*time.Minute)
	colabRT.state = "starting"
	colabRT.phase = fmt.Sprintf("Provisioning Colab G4 GPU (GLM-5.3-Flash %s bpw · %dK ctx)...", tier, ctxSize/1024)
	colabRT.tier = tier
	colabRT.ctxSize = ctxSize
	colabRT.port = port
	colabRT.lastError = ""
	colabRT.startCancel = cancel
	colabRT.mu.Unlock()

	appendColabLog("info", fmt.Sprintf("Launching Colab G4 GLM-5.3-Flash (%s bpw, %dK ctx, local port %d)...", tier, ctxSize/1024, port))

	go func() {
		defer cancel()
		script := filepath.Join(s.colabScriptsDir(), "start.sh")
		cmd := exec.CommandContext(runCtx, "bash", script, tier, "--ctx", fmt.Sprintf("%d", ctxSize), "--port", fmt.Sprintf("%d", port), "--session", colabDefaultSession, "--bg")
		cmd.Dir = s.colabScriptsDir()
		cmd.Env = s.colabCmdEnv(cliPath)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			colabRT.mu.Lock()
			colabRT.state = "error"
			colabRT.phase = "Failed to start launcher"
			colabRT.lastError = err.Error()
			colabRT.mu.Unlock()
			return
		}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			colabRT.mu.Lock()
			colabRT.state = "error"
			colabRT.phase = "Failed to launch start.sh"
			colabRT.lastError = err.Error()
			colabRT.mu.Unlock()
			return
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 512*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(reANSI.ReplaceAllString(scanner.Text(), ""))
			if line == "" {
				continue
			}
			appendColabLog("info", line)
			low := strings.ToLower(line)
			newPhase := ""
			switch {
			case reG4BusyRetry.MatchString(line):
				if m := reG4BusyRetry.FindStringSubmatch(line); len(m) >= 2 {
					newPhase = fmt.Sprintf("Waiting for available Colab G4 GPU slot (Google 503 busy · retry #%s)...", m[1])
				}
			case strings.Contains(low, "build") && strings.Contains(low, "maya"):
				newPhase = "Building Project Maya for RTX PRO 6000 Blackwell (sm_120)..."
			case strings.Contains(low, "download") || strings.Contains(low, "hf_hub") || strings.Contains(low, "fetching"):
				newPhase = fmt.Sprintf("Downloading GLM-5.3-Flash %s bpw weights to Colab G4...", tier)
			case strings.Contains(low, "pack") || strings.Contains(low, "loading"):
				newPhase = "Packing & loading model weights into 96 GB VRAM..."
			case strings.Contains(low, "tunnel"):
				newPhase = fmt.Sprintf("Opening self-healing SSH tunnel on 127.0.0.1:%d...", port)
			}
			if newPhase != "" {
				colabRT.mu.Lock()
				if colabRT.state == "starting" {
					colabRT.phase = newPhase
				}
				colabRT.mu.Unlock()
			}
		}

		waitErr := cmd.Wait()
		if waitErr != nil {
			colabRT.mu.Lock()
			colabRT.state = "error"
			colabRT.phase = "Launch failed — check logs below"
			colabRT.lastError = waitErr.Error()
			colabRT.startCancel = nil
			colabRT.mu.Unlock()
			appendColabLog("error", "start.sh exited with error: "+waitErr.Error())
			return
		}

		// Verify live /v1/models health and auto-register/activate the BEHEMOTH LLM profile!
		if !checkColabTunnelHealth(port) {
			time.Sleep(2 * time.Second)
		}
		if checkColabTunnelHealth(port) {
			profID, perr := s.upsertColabLLMProfile(tier, ctxSize, port, autoActivate)
			if perr != nil {
				log.Printf("[colab-g4] auto-register LLM profile failed: %v", perr)
				appendColabLog("warn", "Tunnel ready, but failed to auto-register LLM profile: "+perr.Error())
			} else {
				appendColabLog("ok", fmt.Sprintf("Auto-registered & activated LLM Profile #%d (http://127.0.0.1:%d/v1)", profID, port))
			}
			colabRT.mu.Lock()
			colabRT.state = "running"
			colabRT.phase = "Colab G4 tunnel healthy & serving GLM-5.3-Flash"
			colabRT.lastError = ""
			colabRT.startCancel = nil
			colabRT.mu.Unlock()
		} else {
			colabRT.mu.Lock()
			colabRT.state = "error"
			colabRT.phase = "Tunnel did not respond on /v1/models"
			colabRT.lastError = fmt.Sprintf("http://127.0.0.1:%d/v1/models did not return 200 OK", port)
			colabRT.startCancel = nil
			colabRT.mu.Unlock()
		}
	}()

	writeJSON(w, http.StatusAccepted, s.colabStatusSnapshot(r.Context(), false))
}

func (s *Server) handleColabG4Stop(w http.ResponseWriter, r *http.Request) {
	colabRT.mu.Lock()
	if colabRT.startCancel != nil {
		colabRT.startCancel()
		colabRT.startCancel = nil
	}
	colabRT.state = "stopping"
	colabRT.phase = "Stopping tunnel and terminating Colab G4 VM to end billing..."
	colabRT.mu.Unlock()

	cliPath := s.findColabCLI()
	if s.colabScriptsReady() {
		stopCtx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(stopCtx, "bash", filepath.Join(s.colabScriptsDir(), "stop.sh"))
		cmd.Dir = s.colabScriptsDir()
		cmd.Env = s.colabCmdEnv(cliPath)
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			appendColabLog("info", firstLinesSummary(string(out), 4))
		}
		if err != nil {
			appendColabLog("warn", "stop.sh warning: "+err.Error())
		}
	}

	colabRT.mu.Lock()
	colabRT.state = "idle"
	colabRT.phase = "Stopped (Colab G4 billing ended)"
	colabRT.lastError = ""
	colabRT.mu.Unlock()
	appendColabLog("ok", "Colab G4 session and tunnel stopped cleanly")

	writeJSON(w, http.StatusOK, s.colabStatusSnapshot(r.Context(), true))
}

func (s *Server) handleColabG4Reconnect(w http.ResponseWriter, r *http.Request) {
	cliPath := s.findColabCLI()
	if cliPath == "" || !s.colabScriptsReady() {
		writeErr(w, http.StatusPreconditionFailed, "Colab G4 scripts are not installed")
		return
	}
	colabRT.mu.Lock()
	port := colabRT.port
	if port <= 0 {
		port = colabDefaultPort
	}
	colabRT.mu.Unlock()

	recCtx, cancel := context.WithTimeout(s.ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(recCtx, "bash", filepath.Join(s.colabScriptsDir(), "tunnel.sh"), colabDefaultSession, fmt.Sprintf("%d", port), "--bg")
	cmd.Dir = s.colabScriptsDir()
	cmd.Env = s.colabCmdEnv(cliPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		appendColabLog("error", "Tunnel reconnect failed: "+firstLine(string(out)+" "+err.Error(), 180))
		writeErr(w, http.StatusInternalServerError, "Tunnel reconnect failed: "+firstLine(string(out)+" "+err.Error(), 180))
		return
	}
	appendColabLog("ok", fmt.Sprintf("Reconnected Colab G4 SSH tunnel on 127.0.0.1:%d", port))
	writeJSON(w, http.StatusOK, s.colabStatusSnapshot(r.Context(), false))
}
