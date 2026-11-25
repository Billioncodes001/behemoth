package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type convSSEFrame struct {
	Event string
	Data  []byte
}

type convStreamHub struct {
	mu   sync.Mutex
	subs map[int64]map[chan convSSEFrame]struct{}
}

var globalConvStreamHub = &convStreamHub{
	subs: make(map[int64]map[chan convSSEFrame]struct{}),
}

func (h *convStreamHub) subscribe(convID int64) (<-chan convSSEFrame, func()) {
	ch := make(chan convSSEFrame, 128)
	h.mu.Lock()
	if h.subs[convID] == nil {
		h.subs[convID] = make(map[chan convSSEFrame]struct{})
	}
	h.subs[convID][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if m := h.subs[convID]; m != nil {
			delete(m, ch)
			if len(m) == 0 {
				delete(h.subs, convID)
			}
		}
		h.mu.Unlock()
	}
}

func (h *convStreamHub) publish(convID int64, event string, payload any) {
	if convID <= 0 {
		return
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	frame := convSSEFrame{Event: event, Data: b}
	h.mu.Lock()
	listeners := h.subs[convID]
	for ch := range listeners {
		select {
		case ch <- frame:
		default:
			// For rapid token deltas, drop oldest queued delta if subscriber lags behind.
			if event == "delta" {
				select {
				case <-ch:
				default:
				}
				select {
				case ch <- frame:
				default:
				}
			}
		}
	}
	h.mu.Unlock()
}

// GET /api/conversations/{id}/stream — real-time Server-Sent Events stream for /chat
// delivering sub-50ms live thinking/text token deltas ("delta"), instant persisted
// tool/message steps ("activity"), and run-state transitions ("status").
func (s *Server) pgConversationStream(w http.ResponseWriter, r *http.Request) {
	_, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := globalConvStreamHub.subscribe(c.ID)
	defer unsub()

	s.chatMu.Lock()
	running := s.chatBusy[s.convBusyKey(c.ID)]
	s.chatMu.Unlock()
	initBytes, _ := json.Marshal(map[string]any{"running": running})
	_, _ = fmt.Fprintf(w, "event: status\ndata: %s\n\n", initBytes)
	flusher.Flush()

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.ctx.Done():
			return
		case <-ping.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case frame := <-ch:
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", frame.Event, frame.Data)
			flusher.Flush()
		}
	}
}
