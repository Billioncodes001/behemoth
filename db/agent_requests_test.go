package db

import (
	"fmt"
	"testing"
	"time"
)

// The kind CHECK constraint used to allow only the original six kinds. The
// migration must widen it (idempotently) so tool_error/resource rows are not
// silently coerced or rejected on databases created before those kinds existed.
func TestEnsureAgentRequestKindsAllowsNewKinds(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	for i := 0; i < 2; i++ { // twice: idempotent
		if err := d.EnsureAgentRequestKinds(); err != nil {
			t.Fatalf("ensure run %d: %v", i+1, err)
		}
	}

	store := d.AgentRequests()
	for _, kind := range []string{AgentRequestKindToolError, AgentRequestKindResource} {
		marker := fmt.Sprintf("__kinds_%s_%d__", kind, time.Now().UnixNano())
		req, err := store.Create(AgentRequestCreate{Kind: kind, Title: marker, Urgency: AgentRequestUrgencyNormal})
		if err != nil {
			t.Fatalf("create %s: %v", kind, err)
		}
		if req.Kind != kind {
			t.Fatalf("kind coerced: want %s got %s", kind, req.Kind)
		}
		t.Cleanup(func() { _, _ = store.Delete(req.ID) })
	}
}