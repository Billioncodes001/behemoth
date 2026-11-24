package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/behemoth/db"
)

// HTTP surface for agent capability requests (report_need inbox).
// GET    /api/agent-requests         — one page + per-status counts
// GET    /api/agent-requests/counts  — per-status counts for the alerts bell
// PATCH  /api/agent-requests/{id}    — lifecycle transition {status}
// DELETE /api/agent-requests/{id}    — remove one request

func agentRequestFilterFromQuery(r *http.Request) db.AgentRequestFilter {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
	return db.AgentRequestFilter{
		Status: q.Get("status"),
		Kind:   q.Get("kind"),
		Agent:  q.Get("agent"),
		TaskID: taskID,
		Query:  q.Get("q"),
		Limit:  limit,
		Offset: offset,
	}
}

// GET /api/agent-requests — one page of agent requests + per-status counts.
func (s *Server) listAgentRequests(w http.ResponseWriter, r *http.Request) {
	st := s.agentRequestStore()
	if st == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	f := agentRequestFilterFromQuery(r)
	items, total, err := st.List(f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	counts, err := st.Counts()
	if err != nil {
		counts = map[string]int{"total": total}
	}
	writeJSON(w, 200, map[string]any{"requests": items, "total": total, "counts": counts})
}

// GET /api/agent-requests/counts — per-status counts for the alerts bell.
func (s *Server) agentRequestCounts(w http.ResponseWriter, r *http.Request) {
	st := s.agentRequestStore()
	if st == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	counts, err := st.Counts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, counts)
}

// PATCH /api/agent-requests/{id} — update the lifecycle status.
func (s *Server) updateAgentRequest(w http.ResponseWriter, r *http.Request) {
	st := s.agentRequestStore()
	if st == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid agent request id")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid request body")
		return
	}
	status := strings.TrimSpace(body.Status)
	if !db.ValidAgentRequestStatus(status) {
		writeErr(w, 400, "status must be one of new/acknowledged/resolved/dismissed")
		return
	}
	req, err := st.SetStatus(id, status)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "agent request not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, req)
}

// DELETE /api/agent-requests/{id} — remove one request.
func (s *Server) deleteAgentRequest(w http.ResponseWriter, r *http.Request) {
	st := s.agentRequestStore()
	if st == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid agent request id")
		return
	}
	_, err = st.Delete(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "agent request not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}
