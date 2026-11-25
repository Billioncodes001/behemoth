package server

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
)

const (
	settingInFlightAgentTurns = "in_flight_agent_turns_v1"
	maxInFlightResumeAge      = 24 * time.Hour
	liveUpdateResumePrompt    = "[System Live-Update Handoff] BEHEMOTH just applied a live platform update and reloaded your session on the updated engine with all newly deployed tools, skills, and fixes active. Continue executing the objective seamlessly from your last completed step in the transcript without repeating already-completed work."
)

type persistedInFlightTurn struct {
	Kind           string `json:"kind"` // "conversation" | "task_main"
	BusyKey        string `json:"busy_key"`
	ConversationID int64  `json:"conversation_id,omitempty"`
	AgentKey       string `json:"agent_key,omitempty"`
	TaskID         string `json:"task_id,omitempty"`
	MainSeg        int    `json:"main_seg,omitempty"`
	OriginalMsg    string `json:"original_msg,omitempty"`
	StartedAtUnix  int64  `json:"started_at_unix"`
}

func (s *Server) registerActiveTurn(entry persistedInFlightTurn) {
	if s == nil || strings.TrimSpace(entry.BusyKey) == "" {
		return
	}
	if entry.StartedAtUnix == 0 {
		entry.StartedAtUnix = time.Now().Unix()
	}
	s.inFlightMu.Lock()
	if s.activeTurns == nil {
		s.activeTurns = make(map[string]persistedInFlightTurn)
	}
	s.activeTurns[entry.BusyKey] = entry
	s.inFlightMu.Unlock()
}

func (s *Server) unregisterActiveTurn(busyKey string) {
	if s == nil || strings.TrimSpace(busyKey) == "" {
		return
	}
	s.inFlightMu.Lock()
	delete(s.activeTurns, busyKey)
	s.inFlightMu.Unlock()
}

// persistActiveTurnsForLiveUpdate snapshots all currently running conversation and
// task main-agent turns into PostgreSQL right before a live-update binary swap so
// the new process immediately marks them busy and continues them from their JSONL
// transcripts without interruption.
func (s *Server) persistActiveTurnsForLiveUpdate() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	s.inFlightMu.Lock()
	if s.liveUpdateTurnsPersisted {
		s.inFlightMu.Unlock()
		return
	}
	list := make([]persistedInFlightTurn, 0, len(s.activeTurns))
	for _, item := range s.activeTurns {
		// Skip credential_processor (it has its own DB queue) and one-shot sealed retests.
		if item.AgentKey == db.CredentialAgentKey || item.AgentKey == db.FindingRetestAgentKey {
			continue
		}
		list = append(list, item)
	}
	s.liveUpdateTurnsPersisted = true
	s.inFlightMu.Unlock()

	if len(list) == 0 {
		_ = s.m.pg.SetSetting(settingInFlightAgentTurns, "")
		return
	}
	b, err := json.Marshal(list)
	if err != nil {
		return
	}
	if err := s.m.pg.SetSetting(settingInFlightAgentTurns, string(b)); err != nil {
		log.Printf("[live-update] failed to persist %d active agent turn(s): %v", len(list), err)
		return
	}
	log.Printf("[live-update] Checkpointed %d active agent session(s) for seamless post-update continuation", len(list))
}

func isLiveUpdateReloadContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	code, _, _, ok := agent.AbortReason(ctx)
	return (ok && code == "live_update_reload") || IsLiveUpdateRestart()
}

// restoreInFlightAgentTurns runs during Server.New startup after LLM & intercept
// wiring are ready. It atomically consumes checkpointed turns from PostgreSQL,
// marks them busy immediately (so UI polling never drops out of running state),
// and continues each turn from its on-disk JSONL transcript on the updated binary.
func (s *Server) restoreInFlightAgentTurns() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	raw, ok, err := s.m.pg.GetSetting(settingInFlightAgentTurns)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return
	}
	// Consume immediately so a single checkpoint is never replayed twice.
	_ = s.m.pg.SetSetting(settingInFlightAgentTurns, "")

	var saved []persistedInFlightTurn
	if err := json.Unmarshal([]byte(raw), &saved); err != nil || len(saved) == 0 {
		return
	}

	cutoff := time.Now().Add(-maxInFlightResumeAge).Unix()
	for _, entry := range saved {
		if entry.StartedAtUnix > 0 && entry.StartedAtUnix < cutoff {
			continue
		}
		switch entry.Kind {
		case "conversation":
			s.resumePersistedConversationTurn(entry)
		case "task_main":
			s.resumePersistedTaskMainTurn(entry)
		}
	}
}

func (s *Server) resumePersistedConversationTurn(entry persistedInFlightTurn) {
	if entry.ConversationID <= 0 || s.m == nil || s.m.pg == nil {
		return
	}
	conv, err := s.m.pg.GetConversation(entry.ConversationID)
	if err != nil || conv == nil {
		return
	}
	if s.resolveChatAgent(conv) == nil {
		return
	}
	busyKey := s.convBusyKey(conv.ID)
	s.chatMu.Lock()
	if s.chatBusy[busyKey] {
		s.chatMu.Unlock()
		return
	}
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()

	s.registerActiveTurn(persistedInFlightTurn{
		Kind:           "conversation",
		BusyKey:        busyKey,
		ConversationID: conv.ID,
		AgentKey:       conv.AgentKey,
		OriginalMsg:    entry.OriginalMsg,
		StartedAtUnix:  entry.StartedAtUnix,
	})
	log.Printf("[live-update] Seamlessly resuming active conversation #%d (%s) onto updated runtime", conv.ID, conv.AgentKey)
	ctx, cancel := s.conversationRunContext(conv.ID, busyKey)
	go s.runConversationTurn(ctx, cancel, conv, liveUpdateResumePrompt, busyKey)
}

func (s *Server) resumePersistedTaskMainTurn(entry persistedInFlightTurn) {
	if strings.TrimSpace(entry.TaskID) == "" || s.m == nil {
		return
	}
	t := s.m.ResolveTask(entry.TaskID)
	if t == nil || !s.taskRuntimeAvailable(t, "mainagent") {
		return
	}
	ma := s.agentsForTask(t).main
	if ma == nil {
		return
	}
	s.chatMu.Lock()
	if s.chatBusy[t.ID] {
		s.chatMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancelCause(s.ctx)
	s.chatBusy[t.ID] = true
	s.chatCancel[t.ID] = cancel
	s.chatMu.Unlock()

	s.registerActiveTurn(persistedInFlightTurn{
		Kind:          "task_main",
		BusyKey:       t.ID,
		TaskID:        t.ID,
		MainSeg:       entry.MainSeg,
		OriginalMsg:   entry.OriginalMsg,
		StartedAtUnix: entry.StartedAtUnix,
	})
	mainSeg := entry.MainSeg
	segPtr := &mainSeg
	log.Printf("[live-update] Seamlessly resuming Task #%s MainAgent turn onto updated runtime", t.ID)
	go func() {
		defer func() {
			if !isLiveUpdateReloadContext(ctx) {
				s.unregisterActiveTurn(t.ID)
			}
			s.finishTaskChat(t.ID, cancel)
		}()
		emit := func(rec db.Activity) {
			rec.MainSeg = segPtr
			s.engine.emitActivity(t, rec)
		}
		maTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
		resume := func() { s.reviveTask(t) }
		s.engine.BeginLLMCall(t.ID)
		_, err := ma.Chat(ctx, maTaskID, mainSeg, s.m.Assets(), t.Store, t.Goal, liveUpdateResumePrompt, emit, t.Notify, resume, t.NotifyGoal, t.NotifyHint)
		s.engine.EndLLMCall(t.ID)
		if err != nil && ctx.Err() == nil {
			s.engine.emitActivity(t, db.Activity{Worker: "mainagent", Kind: "text", IsError: true, Summary: "(Main Agent error: " + err.Error() + ")", MainSeg: segPtr})
		}
	}()
}
