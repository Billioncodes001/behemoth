package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	"github.com/Autumn-27/behemoth/server/browser"
	actool "github.com/Autumn-27/norma/tool"
)

var (
	arsenalProvisionMu  sync.Mutex
	arsenalProvisioning atomic.Bool
)

func ensureArsenalPATH() {
	cur := os.Getenv("PATH")
	parts := strings.Split(cur, string(os.PathListSeparator))
	have := map[string]bool{}
	for _, p := range parts {
		have[p] = true
	}
	var prepend []string
	for _, want := range []string{"/usr/local/bin", "/opt/google-cloud-sdk/bin"} {
		if !have[want] {
			prepend = append(prepend, want)
		}
	}
	if len(prepend) > 0 {
		_ = os.Setenv("PATH", strings.Join(prepend, string(os.PathListSeparator))+string(os.PathListSeparator)+cur)
	}
}

func resolveSetupScriptPath() string {
	candidates := []string{"./setup.sh", "/app/setup.sh"}
	if exe, err := os.Executable(); err == nil && exe != "" {
		candidates = append([]string{filepath.Join(filepath.Dir(exe), "setup.sh")}, candidates...)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

var defaultCommonWebPaths = strings.Join([]string{
	".env", ".env.backup", ".env.example", ".env.local", ".env.production",
	".git/HEAD", ".git/config", ".gitignore", ".htaccess", ".htpasswd", ".svn/entries",
	"robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt", ".well-known/openid-configuration",
	"crossdomain.xml", "clientaccesspolicy.xml", "humans.txt", "README.md", "CHANGELOG.md",
	"composer.json", "composer.lock", "package.json", "yarn.lock", "requirements.txt", "Pipfile", "Dockerfile", "docker-compose.yml",
	"phpinfo.php", "info.php", "test.php", "config.php", "database.php", "settings.php", "wp-config.php.bak", "web.config",
	"admin", "admin/", "admin/login", "admin/dashboard", "administrator", "Console", "console", "manage", "manager", "portal",
	"login", "signin", "auth", "auth/login", "oauth/token", "sso", "register", "signup", "forgot-password", "reset-password",
	"dashboard", "panel", "cpanel", "phpmyadmin", "adminer", "adminer.php", "pma", "kibana", "grafana", "prometheus", "metrics",
	"actuator", "actuator/health", "actuator/env", "actuator/mappings", "actuator/heapdump", "actuator/beans",
	"swagger", "swagger-ui.html", "swagger-ui/", "swagger.json", "openapi.json", "v2/api-docs", "v3/api-docs", "api-docs", "redoc",
	"graphql", "graphiql", "playground", "api", "api/v1", "api/v2", "api/v3", "api/health", "api/status", "api/version", "api/config",
	"api/users", "api/me", "api/profile", "api/admin", "api/search", "api/export", "api/upload",
	"health", "healthz", "readyz", "status", "server-status", "server-info", "nginx_status", "version", "debug", "debug/pprof/",
	"trace", "elmah.axd", "trace.axd", "telescope", "_profiler", "__debug__",
	"uploads", "upload", "files", "static", "assets", "media", "public", "storage", "storage/logs/laravel.log",
	"application/logs", "application/config/config.php", "application/config/database.php", "application/config/routes.php",
	"var/log", "logs", "error.log", "access.log", "debug.log", "error_log",
	"backup", "backups", "backup.zip", "backup.sql", "backup.tar.gz", "db.sql", "dump.sql", "database.sql", "site.zip", "www.zip",
}, "\n") + "\n"

var defaultAPIRoutesWordlist = strings.Join([]string{
	"api", "api/v1", "api/v2", "api/v3", "v1", "v2", "rest", "graphql",
	"api/login", "api/auth", "api/token", "api/refresh", "api/me", "api/user", "api/users",
	"api/account", "api/accounts", "api/admin", "api/settings", "api/config", "api/keys",
	"api/upload", "api/files", "api/documents", "api/export", "api/import", "api/reports",
	"api/orders", "api/invoices", "api/payments", "api/transactions", "api/search", "api/query",
	"api/webhook", "api/webhooks", "api/debug", "api/health", "api/metrics", "api/swagger.json", "openapi.json",
}, "\n") + "\n"

// ensureDefaultWordlists writes built-in reconnaissance & fuzzing wordlists into
// <dataDir>/wordlists/ (and /usr/share/wordlists/behemoth if writable) so ffuf,
// gobuster, dirb, and custom scripts always have reliable wordlists on every OS.
func (s *Server) ensureDefaultWordlists() {
	if s.dataDir == "" {
		return
	}
	dirs := []string{filepath.Join(s.dataDir, "wordlists")}
	if os.Geteuid() == 0 {
		dirs = append(dirs, "/usr/share/wordlists/behemoth")
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		commonPath := filepath.Join(dir, "common.txt")
		if _, err := os.Stat(commonPath); os.IsNotExist(err) {
			_ = os.WriteFile(commonPath, []byte(defaultCommonWebPaths), 0o644)
		}
		apiPath := filepath.Join(dir, "api-routes.txt")
		if _, err := os.Stat(apiPath); os.IsNotExist(err) {
			_ = os.WriteFile(apiPath, []byte(defaultAPIRoutesWordlist), 0o644)
		}
	}
	if os.Geteuid() == 0 {
		if _, err := os.Stat("/usr/share/wordlists/dirb/common.txt"); os.IsNotExist(err) {
			_ = os.MkdirAll("/usr/share/wordlists/dirb", 0o755)
			_ = os.Symlink("/usr/share/wordlists/behemoth/common.txt", "/usr/share/wordlists/dirb/common.txt")
		}
	}
	ensureArsenalPATH()
	if runtime.GOOS == "linux" && flag.Lookup("test.v") == nil {
		go s.autoProvisionLinuxArsenal()
	}
}

type arsenalProvisionState struct {
	SetupSHA256     string `json:"setup_sha256"`
	LastAttemptUnix int64  `json:"last_attempt_unix"`
}

func (s *Server) autoProvisionLinuxArsenal() {
	if flag.Lookup("test.v") != nil {
		return
	}
	ensureArsenalPATH()
	setupPath := resolveSetupScriptPath()
	if setupPath == "" {
		return
	}
	setupBytes, err := os.ReadFile(setupPath)
	if err != nil {
		return
	}
	isRoot := os.Geteuid() == 0
	canSudo := !isRoot && exec.Command("sudo", "-n", "true").Run() == nil
	if !isRoot && !canSudo {
		return
	}

	if !arsenalProvisionMu.TryLock() {
		return
	}
	defer arsenalProvisionMu.Unlock()

	sum := sha256.Sum256(setupBytes)
	wantHash := hex.EncodeToString(sum[:])
	stateFile := filepath.Join(s.dataDir, "wordlists", ".arsenal_setup_sha256")
	metaFile := filepath.Join(s.dataDir, "wordlists", ".arsenal_setup_state.json")
	prevHashBytes, _ := os.ReadFile(stateFile)
	prevHash := strings.TrimSpace(string(prevHashBytes))

	var meta arsenalProvisionState
	if rawMeta, merr := os.ReadFile(metaFile); merr == nil {
		_ = json.Unmarshal(rawMeta, &meta)
		if prevHash == "" && meta.SetupSHA256 != "" {
			prevHash = meta.SetupSHA256
		}
	}

	// Binaries whose absence triggers a (re)run of ./setup.sh arsenal so a fresh
	// or partially provisioned host/container converges to the full arsenal.
	coreExpected := []string{
		"tor", "tesseract", "nuclei", "subfinder", "ffuf", "gobuster", "trivy", "grype", "rustscan", "mysql", "psql",
		"msfvenom", "impacket-secretsdump", "responder", "linpeas.sh", "winpeas.exe", "vol", "az", "gcloud", "pacu", "scout",
	}
	var missingBins []string
	for _, bin := range coreExpected {
		if _, lookErr := exec.LookPath(bin); lookErr != nil {
			missingBins = append(missingBins, bin)
		}
	}
	missingCore := len(missingBins) > 0
	if prevHash == wantHash && !missingCore {
		return
	}
	// If setup.sh hash hasn't changed (we already ran this exact setup.sh version)
	// and only an optional/unavailable upstream package is missing, wait 6h before
	// retrying so rapid live-update restarts never trigger back-to-back apt runs.
	if prevHash == wantHash && missingCore && meta.LastAttemptUnix > 0 &&
		time.Since(time.Unix(meta.LastAttemptUnix, 0)) < 6*time.Hour {
		return
	}

	arsenalProvisioning.Store(true)
	defer arsenalProvisioning.Store(false)

	log.Printf("[arsenal] Auto-provisioning Linux security CLI, OCR & extended arsenal via %s in background (missing=%d)...", setupPath, len(missingBins))
	ctx, cancel := context.WithTimeout(s.ctx, 35*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if isRoot {
		cmd = exec.CommandContext(ctx, "bash", setupPath, "arsenal")
	} else {
		cmd = exec.CommandContext(ctx, "sudo", "-n", "bash", setupPath, "arsenal")
	}
	cmd.Dir = filepath.Dir(setupPath)
	out, runErr := cmd.CombinedOutput()
	ensureArsenalPATH()

	newMeta := arsenalProvisionState{
		SetupSHA256:     wantHash,
		LastAttemptUnix: time.Now().Unix(),
	}
	if b, jerr := json.Marshal(newMeta); jerr == nil {
		_ = os.WriteFile(metaFile, b, 0o644)
	}
	_ = os.WriteFile(stateFile, []byte(wantHash+"\n"), 0o644)

	if runErr != nil {
		log.Printf("[arsenal] Background provisioning finished with warning: %v (%s)", runErr, firstLine(string(out), 200))
	} else {
		log.Printf("[arsenal] Linux security CLI, OCR & extended arsenal provisioned successfully")
	}
}

func (s *Server) resolveWordlistPaths() map[string]string {
	out := map[string]string{}
	candidates := []struct {
		key   string
		paths []string
	}{
		{
			key: "common_web",
			paths: []string{
				"/usr/share/wordlists/behemoth/common.txt",
				"/usr/share/wordlists/dirb/common.txt",
				"/usr/share/seclists/Discovery/Web-Content/common.txt",
				filepath.Join(s.dataDir, "wordlists", "common.txt"),
			},
		},
		{
			key: "api_routes",
			paths: []string{
				"/usr/share/wordlists/behemoth/api-routes.txt",
				filepath.Join(s.dataDir, "wordlists", "api-routes.txt"),
			},
		},
	}
	for _, c := range candidates {
		for _, p := range c.paths {
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
				out[c.key] = p
				break
			}
		}
	}
	return out
}

func (s *Server) arsenalTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListSecurityArsenal(),
		s.toolRunSecurityTool(),
		s.toolBrowserInspect(),
		s.toolVerifyXSSExecution(),
		s.toolDetectDeceptionAndHoneypot(),
		s.toolProxiedTCPRelay(),
		s.toolCreateCallbackListener(),
		s.toolPollCallbackEvents(),
		s.toolManageAuthSessions(),
		s.toolVerifyAccessControlMatrix(),
		s.toolAuditFrontendAPISurface(),
		s.toolVerifyEndpointIdempotency(),
		s.toolAuditSourceRoutes(),
	}
}

func (s *Server) toolListSecurityArsenal() actool.CoreTool {
	return roTool("list_security_arsenal",
		"Inspect all offensive security CLI binaries, structured Tool Catalog scanners, and fuzzing wordlists currently installed and ready on this BEHEMOTH host.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			cliNames := []string{
				"nmap", "nuclei", "subfinder", "httpx-pd", "httpx", "dnsx",
				"ffuf", "gobuster", "dirb", "sqlmap", "nikto", "whatweb",
				"wafw00f", "hydra", "sslscan", "dig", "whois", "nc",
				"socat", "openssl", "curl", "python3", "rg", "jq", "tor", "tesseract", "mysql", "psql",
				"rustscan", "masscan", "smtp-user-enum", "onesixtyone", "snmpwalk",
				"impacket-secretsdump", "impacket-GetNPUsers", "bloodhound-python",
				"msfvenom", "responder", "linpeas.sh", "winpeas.exe", "vol", "volatility", "trivy", "grype", "semgrep",
				"aws", "az", "gcloud", "pacu", "scout",
			}
			installed := make([]map[string]string, 0, len(cliNames))
			var missing []string
			for _, bin := range cliNames {
				if p, err := exec.LookPath(bin); err == nil {
					installed = append(installed, map[string]string{"binary": bin, "path": p})
				} else {
					missing = append(missing, bin)
				}
			}
			var catalogIDs []map[string]any
			if s.toolCatalog != nil {
				for _, ct := range s.toolCatalog.List() {
					_, hasBin := exec.LookPath(ct.Command)
					catalogIDs = append(catalogIDs, map[string]any{
						"id":          ct.ID,
						"name":        ct.Name,
						"category":    ct.Category,
						"command":     ct.Command,
						"available":   hasBin == nil,
						"description": ct.Description,
					})
				}
			}
			return jsonResult(map[string]any{
				"provisioning_in_progress": arsenalProvisioning.Load(),
				"installed_cli":            installed,
				"missing_cli":              missing,
				"wordlists":                s.resolveWordlistPaths(),
				"catalog_tools":            catalogIDs,
			})
		})
}

func (s *Server) toolRunSecurityTool() actool.CoreTool {
	return wrTool("run_security_tool",
		"Execute a structured built-in scanner from the BEHEMOTH Tool Catalog (e.g. nmap-scan, subfinder, httpx-probe, gobuster-scan, ffuf-fuzz, dirb-scan, nikto-scan, nuclei-scan, sqlmap-inject) with automatic argument assembly and parsed output.",
		objSchema(map[string]any{
			"tool_id":         strParam("Catalog tool ID (e.g. nmap-scan, subfinder, httpx-probe, gobuster-scan, ffuf-fuzz, dirb-scan, nikto-scan, nuclei-scan, sqlmap-inject)"),
			"params":          map[string]any{"type": "object", "description": "Key-value parameters for the tool (e.g. {\"target\":\"example.com\"} or {\"url\":\"https://example.com/FUZZ\",\"wordlist\":\"...\"})"},
			"timeout_seconds": map[string]any{"type": "integer", "description": "Optional timeout in seconds (default 180, max 900)"},
		}, "tool_id", "params"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.toolCatalog == nil || s.toolExecutor == nil {
				return actool.Errorf("tool catalog executor is not initialized"), nil
			}
			var a struct {
				ToolID         string         `json:"tool_id"`
				Params         map[string]any `json:"params"`
				TimeoutSeconds int            `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			a.ToolID = strings.TrimSpace(a.ToolID)
			if a.ToolID == "" {
				return actool.Errorf("tool_id is required"), nil
			}
			strParams := make(map[string]string, len(a.Params))
			for k, v := range a.Params {
				if v != nil {
					strParams[k] = fmt.Sprint(v)
				}
			}
			// Auto-substitute default wordlist if omitted or missing on this OS
			wls := s.resolveWordlistPaths()
			if wl, ok := strParams["wordlist"]; !ok || strings.TrimSpace(wl) == "" {
				if common := wls["common_web"]; common != "" {
					if a.ToolID == "gobuster-scan" || a.ToolID == "ffuf-fuzz" || a.ToolID == "dirb-scan" {
						strParams["wordlist"] = common
					}
				}
			} else if _, err := os.Stat(wl); os.IsNotExist(err) && wls["common_web"] != "" {
				strParams["wordlist"] = wls["common_web"]
			}

			// Auto-inject the BEHEMOTH private nuclei template repo (fed by verified
			// Patch Monitor exploits) when the caller didn't specify templates.
			if a.ToolID == "nuclei-scan" {
				if tpl, ok := strParams["templates"]; !ok || strings.TrimSpace(tpl) == "" {
					if dir := s.customNucleiTemplateDir(); dir != "" {
						strParams["templates"] = dir
					}
				}
			}

			timeout := 180 * time.Second
			if a.TimeoutSeconds > 0 {
				if a.TimeoutSeconds > 900 {
					a.TimeoutSeconds = 900
				}
				timeout = time.Duration(a.TimeoutSeconds) * time.Second
			}
			runCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			res, err := s.toolExecutor.Execute(runCtx, a.ToolID, strParams)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("tool execution error: %v", err)), nil
			}
			out := res.Output
			if len(out) > 28000 {
				out = out[:28000] + "\n...[truncated]..."
			}
			return jsonResult(map[string]any{
				"tool_id":     res.ToolID,
				"status":      res.Status,
				"exit_code":   res.ExitCode,
				"duration_ms": res.Duration.Milliseconds(),
				"parsed":      res.Parsed,
				"output":      out,
				"error":       res.Error,
			})
		})
}

// customNucleiTemplateDir returns the BEHEMOTH private nuclei template directory
// (fed by verified Patch Monitor exploits) when it exists and is non-empty.
func (s *Server) customNucleiTemplateDir() string {
	if s.patchMon == nil {
		return ""
	}
	dir := s.patchMon.NucleiTemplatesDir()
	if dir == "" {
		return ""
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return ""
	}
	return dir
}

func (s *Server) toolVerifyXSSExecution() actool.CoreTool {
	return roTool("verify_xss_execution",
		"Execute a JavaScript/XSS payload against a URL in headless Chromium and report hard execution evidence: alert dialog fired, in-page DOM marker set, and/or unescaped payload reflection in the live DOM. Use this to AUTOMATICALLY verify reflected/DOM XSS before reporting a finding (replaces manual 'open in browser and watch for the alert').",
		objSchema(map[string]any{
			"url":             strParam("Target URL. The payload is appended as query parameter ?<param>=<payload> when 'param' is given; otherwise the payload must already be embedded in this URL"),
			"param":           strParam("Optional query parameter name to inject the payload into (e.g. 'q', 'search', 'name')"),
			"payload":         strParam("Optional JS payload; default is <svg/onload=\"window.__behemothXss=true;alert('behemoth_xss_probe')\">"),
			"timeout_seconds": map[string]any{"type": "integer", "description": "Optional execution wait in seconds (default 30, max 90)"},
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.browserScraper == nil {
				return actool.Errorf("headless browser scraper is not initialized"), nil
			}
			var a struct {
				URL            string `json:"url"`
				Param          string `json:"param"`
				Payload        string `json:"payload"`
				TimeoutSeconds int    `json:"timeout_seconds"`
			}
			_ = json.Unmarshal(in, &a)
			a.URL = strings.TrimSpace(a.URL)
			if a.URL == "" {
				return actool.Errorf("url is required"), nil
			}
			to := 30 * time.Second
			if a.TimeoutSeconds > 0 && a.TimeoutSeconds <= 90 {
				to = time.Duration(a.TimeoutSeconds) * time.Second
			}
			runCtx, cancel := context.WithTimeout(ctx, to)
			defer cancel()
			res, err := s.browserScraper.VerifyXSS(runCtx, browser.XSSVerifyRequest{
				URL:     a.URL,
				Param:   strings.TrimSpace(a.Param),
				Payload: a.Payload,
				Timeout: to,
			})
			if err != nil {
				return actool.Errorf(fmt.Sprintf("verify_xss_execution failed: %v", err)), nil
			}
			return jsonResult(map[string]any{
				"url":              res.URL,
				"payload":          res.Payload,
				"confirmed":        res.Confirmed,
				"dialog_fired":     res.DialogFired,
				"dialog_message":   res.DialogMessage,
				"dom_marker":       res.DOMMarker,
				"reflection_raw":   res.ReflectionRaw,
				"console_messages": res.ConsoleMessages,
				"evidence":         res.Evidence,
				"error":            res.Error,
				"duration_ms":      res.Duration.Milliseconds(),
			})
		})
}

func (s *Server) toolBrowserInspect() actool.CoreTool {
	return roTool("browser_inspect",
		"Render a target URL in headless Chromium and extract the JavaScript-rendered page title and DOM text content (ideal for SPAs, client-side routers, WAF challenges, and dynamic login forms).",
		objSchema(map[string]any{
			"url":             strParam("Target http:// or https:// URL to render"),
			"timeout_seconds": map[string]any{"type": "integer", "description": "Optional render timeout in seconds (default 25)"},
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.browserScraper == nil {
				return actool.Errorf("headless browser scraper is not initialized"), nil
			}
			var a struct {
				URL            string `json:"url"`
				TimeoutSeconds int    `json:"timeout_seconds"`
			}
			_ = json.Unmarshal(in, &a)
			a.URL = strings.TrimSpace(a.URL)
			if a.URL == "" {
				return actool.Errorf("url is required"), nil
			}
			to := 25 * time.Second
			if a.TimeoutSeconds > 0 && a.TimeoutSeconds <= 90 {
				to = time.Duration(a.TimeoutSeconds) * time.Second
			}
			runCtx, cancel := context.WithTimeout(ctx, to)
			defer cancel()
			res, err := s.browserScraper.Handle(runCtx, browser.BrowserRequest{
				URL:     a.URL,
				Action:  browser.ActionContent,
				Timeout: to,
			})
			if err != nil {
				return actool.Errorf(fmt.Sprintf("browser_inspect failed: %v", err)), nil
			}
			content := res.Content
			if len(content) > 25000 {
				content = content[:25000] + "\n...[truncated]..."
			}
			return jsonResult(map[string]any{
				"url":     a.URL,
				"title":   res.Title,
				"success": res.Success,
				"content": content,
				"error":   res.Error,
			})
		})
}
