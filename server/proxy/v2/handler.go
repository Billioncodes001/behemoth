package proxyv2

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Handler provides HTTP API endpoints for the proxy pool v2.
// Uses standard library http.ServeMux (no external router dependency).
type Handler struct {
	pool *Pool
}

// NewHandler creates a new Handler.
func NewHandler(pool *Pool) *Handler {
	return &Handler{pool: pool}
}

// RegisterRoutes registers all proxy pool API routes on a ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Config endpoints
	mux.HandleFunc("GET /api/v2/proxy-pool/config", h.handleGetConfig)
	mux.HandleFunc("PUT /api/v2/proxy-pool/config", h.handleUpdateConfig)
	// Proxy CRUD
	mux.HandleFunc("GET /api/v2/proxy-pool/proxies", h.handleListProxies)
	mux.HandleFunc("POST /api/v2/proxy-pool/proxies", h.handleImportProxies)
	mux.HandleFunc("POST /api/v2/proxy-pool/import", h.handleImportProxies)
	mux.HandleFunc("GET /api/v2/proxy-pool/proxies/", h.handleGetProxy)  // trailing slash for path param
	mux.HandleFunc("PUT /api/v2/proxy-pool/proxies/", h.handleUpdateProxy)
	mux.HandleFunc("DELETE /api/v2/proxy-pool/proxies/", h.handleDeleteProxy)
	// Proxy actions
	mux.HandleFunc("POST /api/v2/proxy-pool/proxies/", h.handleProxyAction) // test, toggle
	mux.HandleFunc("POST /api/v2/proxy-pool/action", h.handleProxyActionBody)
	// Pool actions
	mux.HandleFunc("POST /api/v2/proxy-pool/test-all", h.handleTestAll)
	mux.HandleFunc("POST /api/v2/proxy-pool/clear-failed", h.handleClearFailed)
	mux.HandleFunc("POST /api/v2/proxy-pool/rotate", h.handleForceRotate)
	mux.HandleFunc("GET /api/v2/proxy-pool/rotate", h.handleForceRotate)
	// Stats & logs
	mux.HandleFunc("GET /api/v2/proxy-pool/stats", h.handleStats)
	mux.HandleFunc("GET /api/v2/proxy-pool/logs", h.handleLogs)
}

// handleGetConfig returns the pool configuration.
func (h *Handler) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, h.pool.GetConfig())
}

// handleUpdateConfig updates the pool configuration.
func (h *Handler) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg ProxyPoolConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := h.pool.UpdateConfig(&cfg); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, cfg)
}

// handleListProxies returns all proxies in the pool.
func (h *Handler) handleListProxies(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, h.pool.GetProxies())
}

// handleImportProxies imports proxies from text data.
func (h *Handler) handleImportProxies(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data       string     `json:"data"`
		DefaultType ProxyType `json:"default_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.DefaultType == "" { req.DefaultType = ProxyTypeHTTP }
	result, err := h.pool.ImportProxies(req.Data, req.DefaultType)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, result)
}

// handleGetProxy returns a single proxy by ID.
func (h *Handler) handleGetProxy(w http.ResponseWriter, r *http.Request) {
	id := extractProxyID(r.URL.Path)
	for _, px := range h.pool.GetProxies() {
		if px.ID == id { respondJSON(w, http.StatusOK, px); return }
	}
	respondError(w, http.StatusNotFound, "proxy not found")
}

// handleUpdateProxy updates a proxy's properties.
func (h *Handler) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	id := extractProxyID(r.URL.Path)
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON"); return
	}
	if err := h.pool.UpdateProxy(id, updates); err != nil {
		respondError(w, http.StatusNotFound, err.Error()); return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// handleDeleteProxy removes a proxy from the pool.
func (h *Handler) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	id := extractProxyID(r.URL.Path)
	if err := h.pool.RemoveProxy(id); err != nil {
		respondError(w, http.StatusNotFound, err.Error()); return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleProxyAction handles test and toggle actions on a proxy.
func (h *Handler) handleProxyAction(w http.ResponseWriter, r *http.Request) {
	id := extractProxyID(r.URL.Path)
	action := strings.TrimPrefix(r.URL.Path, "/api/v2/proxy-pool/proxies/"+id+"/")

	switch action {
	case "test":
		result, err := h.pool.TestProxy(id)
		if err != nil { respondError(w, http.StatusNotFound, err.Error()); return }
		respondJSON(w, http.StatusOK, result)
	case "toggle":
		if err := h.pool.ToggleProxyActive(id); err != nil {
			respondError(w, http.StatusNotFound, err.Error()); return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "toggled"})
	default:
		respondError(w, http.StatusNotFound, "unknown action: "+action)
	}
}

// handleTestAll tests all proxies concurrently.
func (h *Handler) handleTestAll(w http.ResponseWriter, r *http.Request) {
	results, err := h.pool.TestAllProxies(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Count results
	total, passed, failed := len(results), 0, 0
	for _, res := range results {
		if res.Success { passed++ } else { failed++ }
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
		"summary": map[string]int{"total": total, "passed": passed, "failed": failed},
	})
}

// handleProxyActionBody handles JSON-body proxy actions ({id, action}).
func (h *Handler) handleProxyActionBody(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	switch req.Action {
	case "test":
		result, err := h.pool.TestProxy(req.ID)
		if err != nil {
			respondError(w, http.StatusNotFound, err.Error())
			return
		}
		respondJSON(w, http.StatusOK, result)
	case "toggle", "activate", "deactivate":
		if err := h.pool.ToggleProxyActive(req.ID); err != nil {
			respondError(w, http.StatusNotFound, err.Error())
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "toggled"})
	default:
		respondError(w, http.StatusBadRequest, "unknown action: "+req.Action)
	}
}

// handleClearFailed removes all failed proxies.
func (h *Handler) handleClearFailed(w http.ResponseWriter, r *http.Request) {
	removed, err := h.pool.ClearFailedProxies()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"removed": removed, "cleared": removed})
}

// handleForceRotate forces proxy rotation.
func (h *Handler) handleForceRotate(w http.ResponseWriter, r *http.Request) {
	var req struct { Reason string `json:"reason"` }
	json.NewDecoder(r.Body).Decode(&req)
	if req.Reason == "" { req.Reason = "manual" }
	proxy, err := h.pool.ForceRotate(req.Reason)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, proxy)
}

// handleStats returns pool statistics.
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, h.pool.GetStats())
}

// handleLogs returns recent switch logs.
func (h *Handler) handleLogs(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, h.pool.GetLogs())
}

// respondJSON writes a JSON response.
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// respondError writes an error JSON response.
func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

// extractProxyID extracts the proxy ID from URL path like /api/v2/proxy-pool/proxies/{id}/...
func extractProxyID(path string) string {
	// Path format: /api/v2/proxy-pool/proxies/{id} or /api/v2/proxy-pool/proxies/{id}/action
	prefix := "/api/v2/proxy-pool/proxies/"
	if !strings.HasPrefix(path, prefix) { return "" }
	rest := strings.TrimPrefix(path, prefix)
	if idx := strings.Index(rest, "/"); idx != -1 {
		return rest[:idx]
	}
	return rest
}