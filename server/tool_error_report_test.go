package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/behemoth/db"
)

type fakeToolErrorStore struct {
	created []db.AgentRequestCreate
}

func (f *fakeToolErrorStore) Create(req db.AgentRequestCreate) (*db.AgentRequest, error) {
	f.created = append(f.created, req)
	return &db.AgentRequest{ID: int64(len(f.created)), Kind: req.Kind, Title: req.Title}, nil
}

func TestToolErrorTrackerReportsAfterThresholdAndDedupes(t *testing.T) {
	store := &fakeToolErrorStore{}
	tr := newToolErrorTracker()

	for i := 0; i < toolErrorThreshold-1; i++ {
		if tr.record(store, "sqlmap", "worker", 7, "timeout") {
			t.Fatalf("failure %d must not report yet", i+1)
		}
	}
	if len(store.created) != 0 {
		t.Fatalf("expected no request below threshold, got %d", len(store.created))
	}
	if !tr.record(store, "sqlmap", "worker", 7, "dial tcp: i/o timeout") {
		t.Fatal("expected a request once the threshold is reached")
	}
	if len(store.created) != 1 {
		t.Fatalf("expected exactly one request, got %d", len(store.created))
	}
	got := store.created[0]
	if got.Kind != db.AgentRequestKindToolError || got.TaskID == nil || *got.TaskID != 7 {
		t.Fatalf("unexpected request: %+v", got)
	}
	if got.AgentKey != "worker" || got.Urgency != db.AgentRequestUrgencyNormal {
		t.Fatalf("unexpected attribution: %+v", got)
	}
	if !strings.Contains(got.Details, "dial tcp: i/o timeout") || !strings.Contains(got.Details, "Recommendation:") {
		t.Fatalf("details should carry the last error and a recommendation: %q", got.Details)
	}

	// Same tool+task inside the cooldown window: counts failures but stays quiet.
	for i := 0; i < toolErrorThreshold-1; i++ {
		if tr.record(store, "sqlmap", "worker", 7, "timeout again") {
			t.Fatalf("cooldown failure %d must not report again", i+1)
		}
	}
	if len(store.created) != 1 {
		t.Fatalf("expected cooldown to suppress duplicates, got %d requests", len(store.created))
	}

	// A different task is independent.
	for i := 0; i < toolErrorThreshold; i++ {
		tr.record(store, "sqlmap", "worker", 8, "boom")
	}
	if len(store.created) != 2 {
		t.Fatalf("expected an independent request for the other task, got %d", len(store.created))
	}
}

func TestToolErrorTrackerIgnoresEmptyToolAndNilStore(t *testing.T) {
	tr := newToolErrorTracker()
	if tr.record(nil, "nuclei", "worker", 1, "x") {
		t.Fatal("nil store must not report")
	}
	store := &fakeToolErrorStore{}
	for i := 0; i < toolErrorThreshold; i++ {
		if tr.record(store, "", "worker", 1, "x") {
			t.Fatal("empty tool key must not report")
		}
	}
	if len(store.created) != 0 {
		t.Fatalf("expected no requests, got %d", len(store.created))
	}
}
