package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
)

func TestTaskExecutionPausedIncludesLiveUpdateAndShutdown(t *testing.T) {
	if !taskExecutionPaused(agent.AbortLiveUpdateReload) {
		t.Fatal("expected AbortLiveUpdateReload to return running worker intents to open")
	}
	if !taskExecutionPaused(agent.AbortShutdown) {
		t.Fatal("expected AbortShutdown to return running worker intents to open instead of marking blocked")
	}
}

func TestLiveUpdateConversationPersistAndSeamlessResume(t *testing.T) {
	t.Cleanup(func() {
		liveUpdateRestart.Store(false)
	})

	var llmCalls atomic.Int32
	fakeLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id":      "chatcmpl-live-resume",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4o-mini",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "Resumed seamlessly on updated runtime after live update.",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     42,
				"completion_tokens": 12,
				"total_tokens":      54,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer fakeLLM.Close()

	m := proxyTestManager(t)
	_, _ = m.pg.Exec(`DELETE FROM llm_profiles`)
	profID, err := m.pg.SaveProfile(&db.LLMProfile{
		Name:      "openai-live-resume",
		Format:    "openai",
		BaseURL:   fakeLLM.URL + "/v1",
		Model:     "gpt-4o-mini",
		APIKey:    "sk-test-key",
		IsDefault: true,
		Streaming: false,
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	_ = m.pg.SetActiveProfile(profID)

	dir := t.TempDir()
	ctx1, cancel1 := context.WithCancel(context.Background())
	s1 := New(ctx1, m, dir, dir, dir)

	conv, err := m.pg.CreateConversation("auto", "Live Update Continuity Test", nil)
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	_, _ = m.pg.AppendConvActivity(conv.ID, db.Activity{
		Worker:  "user",
		Kind:    "user",
		Summary: "Continue full assessment without stopping on updates",
		Detail:  "Continue full assessment without stopping on updates",
	})

	busyKey := s1.convBusyKey(conv.ID)
	s1.registerActiveTurn(persistedInFlightTurn{
		Kind:           "conversation",
		BusyKey:        busyKey,
		ConversationID: conv.ID,
		AgentKey:       "auto",
		OriginalMsg:    "Continue full assessment without stopping on updates",
	})

	// Simulate live-update handoff from old process s1 -> new process s2.
	liveUpdateRestart.Store(true)
	s1.persistActiveTurnsForLiveUpdate()
	cancel1()
	s1.Close()
	liveUpdateRestart.Store(false)

	// Verify checkpoint was written to PostgreSQL before s2 boots.
	rawSaved, ok, _ := m.pg.GetSetting(settingInFlightAgentTurns)
	if !ok || !strings.Contains(rawSaved, busyKey) {
		t.Fatalf("expected %s persisted in settings, got ok=%v raw=%q", busyKey, ok, rawSaved)
	}

	// Boot new Server instance s2 — it must consume the checkpoint and resume conv automatically!
	ctx2, cancel2 := context.WithCancel(context.Background())
	s2 := New(ctx2, m, dir, dir, dir)
	defer func() {
		cancel2()
		s2.Close()
	}()

	deadline := time.Now().Add(8 * time.Second)
	resumedCompleted := false
	for time.Now().Before(deadline) {
		acts, _, aerr := m.pg.ConvActivityList(conv.ID, 0, 50)
		if aerr == nil {
			for _, a := range acts {
				if strings.Contains(a.Summary, "Resumed seamlessly on updated runtime") || strings.Contains(a.Detail, "Resumed seamlessly on updated runtime") {
					resumedCompleted = true
					break
				}
			}
		}
		if resumedCompleted {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !resumedCompleted || llmCalls.Load() == 0 {
		acts, _, _ := m.pg.ConvActivityList(conv.ID, 0, 50)
		t.Fatalf("expected s2 to automatically resume conversation #%d after live update (llmCalls=%d); activities=%+v", conv.ID, llmCalls.Load(), acts)
	}

	// Verify setting was consumed so subsequent restarts don't replay finished turns.
	afterSaved, _, _ := m.pg.GetSetting(settingInFlightAgentTurns)
	if strings.TrimSpace(afterSaved) != "" {
		t.Fatalf("expected %s setting cleared after resume, got %q", settingInFlightAgentTurns, afterSaved)
	}
}
