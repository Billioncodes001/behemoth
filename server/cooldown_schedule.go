package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/behemoth/agent"
	"github.com/Autumn-27/behemoth/db"
	actool "github.com/Autumn-27/norma/tool"
)

const settingCooldownResumeJobs = "cooldown_resume_jobs_v1"

// CooldownResumeJob represents a persisted one-shot or cron-interval continuation
// scheduled by an agent (e.g. when cooling down between authenticated-page test
// batches on commercial proxies like Webshare so the session automatically wakes
// back up once the cooldown window elapses).
type CooldownResumeJob struct {
	ID                    string `json:"id"`
	TargetType            string `json:"target_type"` // "conversation" | "task"
	ConversationID        int64  `json:"conversation_id,omitempty"`
	TaskID                int64  `json:"task_id,omitempty"`
	AgentKey              string `json:"agent_key,omitempty"`
	Domain                string `json:"domain,omitempty"`
	Reason                string `json:"reason"`
	ResumePrompt          string `json:"resume_prompt"`
	NextFireUnix          int64  `json:"next_fire_unix"`
	NextFireISO           string `json:"next_fire_iso"`
	RepeatIntervalMinutes int    `json:"repeat_interval_minutes,omitempty"` // >0 = cron-style recurring batch waves
	MaxRuns               int    `json:"max_runs"`                          // default 1 (one-shot); >1 for multi-wave cron
	RunsCompleted         int    `json:"runs_completed"`
	Enabled               bool   `json:"enabled"`
	CreatedAtUnix         int64  `json:"created_at_unix"`
	LastFiredUnix         int64  `json:"last_fired_unix,omitempty"`
}

var cooldownJobsMu sync.Mutex

func (s *Server) loadCooldownResumeJobsLocked() []CooldownResumeJob {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil
	}
	raw, ok, err := s.m.pg.GetSetting(settingCooldownResumeJobs)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	var jobs []CooldownResumeJob
	if err := json.Unmarshal([]byte(raw), &jobs); err != nil {
		return nil
	}
	return jobs
}

func (s *Server) saveCooldownResumeJobsLocked(jobs []CooldownResumeJob) error {
	if s == nil || s.m == nil || s.m.pg == nil {
		return fmt.Errorf("database is not initialized")
	}
	if len(jobs) == 0 {
		return s.m.pg.SetSetting(settingCooldownResumeJobs, "")
	}
	b, err := json.Marshal(jobs)
	if err != nil {
		return err
	}
	return s.m.pg.SetSetting(settingCooldownResumeJobs, string(b))
}

func (s *Server) cooldownScheduleTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolScheduleCooldownResume(),
		s.toolListCooldownSchedules(),
		s.toolCancelCooldownSchedule(),
	}
}

func (s *Server) toolScheduleCooldownResume() actool.CoreTool {
	return wrTool("schedule_cooldown_resume",
		"Schedule an automatic cooldown continuation (one-shot timer or cron-style recurring interval) that wakes the current Chat conversation or Task back up after the target/proxy has cooled down. ALWAYS call this when pausing authenticated-page testing on commercial proxies (e.g. after 5 login attempts or a 429/403/CAPTCHA cooldown) so BEHEMOTH automatically resumes your exact next batch without manual intervention!",
		objSchema(map[string]any{
			"cooldown_minutes":        map[string]any{"type": "integer", "description": "Minutes to wait before firing the next continuation wave (default 35, min 1, max 1440)"},
			"resume_prompt":           strParam("Exact continuation checkpoint & instructions for the resumed run (include domain, credentials/batches already tested, attempt count used, and the next batch to execute)"),
			"domain":                  strParam("Target domain or host cooling down (e.g. 'portal.example.com')"),
			"reason":                  strParam("Why cooldown was scheduled (e.g. 'Reached 5/hour commercial proxy auth-page batch cap; cooling down before batch 2')"),
			"repeat_interval_minutes": map[string]any{"type": "integer", "description": "Optional cron interval in minutes for multi-wave batch testing (0 = one-shot resume; e.g. 45 = repeat every 45m up to max_runs)"},
			"max_runs":                map[string]any{"type": "integer", "description": "Total continuation waves to run (default 1 for one-shot; set 2–24 when repeat_interval_minutes > 0)"},
			"task_id":                 map[string]any{"type": "integer", "description": "Optional explicit Task ID (auto-detected when called inside a Task or Chat session)"},
			"conversation_id":         map[string]any{"type": "integer", "description": "Optional explicit Conversation ID (auto-detected when called inside /chat)"},
		}, "resume_prompt"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil || s.m == nil || s.m.pg == nil {
				return actool.Errorf("server database is not initialized"), nil
			}
			var a struct {
				CooldownMinutes       int    `json:"cooldown_minutes"`
				ResumePrompt          string `json:"resume_prompt"`
				Domain                string `json:"domain"`
				Reason                string `json:"reason"`
				RepeatIntervalMinutes int    `json:"repeat_interval_minutes"`
				MaxRuns               int    `json:"max_runs"`
				TaskID                int64  `json:"task_id"`
				ConversationID        int64  `json:"conversation_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			a.ResumePrompt = strings.TrimSpace(a.ResumePrompt)
			if a.ResumePrompt == "" {
				return actool.Errorf("resume_prompt is required so the resumed session knows what batch to continue"), nil
			}
			if a.CooldownMinutes <= 0 {
				a.CooldownMinutes = 35
			}
			if a.CooldownMinutes > 1440 {
				a.CooldownMinutes = 1440
			}
			if a.RepeatIntervalMinutes < 0 {
				a.RepeatIntervalMinutes = 0
			}
			if a.RepeatIntervalMinutes > 1440 {
				a.RepeatIntervalMinutes = 1440
			}
			if a.MaxRuns <= 0 {
				if a.RepeatIntervalMinutes > 0 {
					a.MaxRuns = 3
				} else {
					a.MaxRuns = 1
				}
			}
			if a.MaxRuns > 24 {
				a.MaxRuns = 24
			}

			ri := agent.RunInfoFrom(ctx)
			convID := a.ConversationID
			taskID := a.TaskID
			if convID <= 0 && strings.HasPrefix(ri.SessionID, "conv-") {
				if parsed, err := strconv.ParseInt(strings.TrimPrefix(ri.SessionID, "conv-"), 10, 64); err == nil && parsed > 0 {
					convID = parsed
				}
			}
			if taskID <= 0 && ri.TaskID > 0 {
				taskID = ri.TaskID
			}
			if convID <= 0 && taskID <= 0 {
				return actool.Errorf("could not auto-detect active conversation_id or task_id — pass task_id or conversation_id explicitly"), nil
			}

			targetType := "conversation"
			agentKey := ""
			if taskID > 0 && convID <= 0 {
				targetType = "task"
			} else if c, err := s.m.pg.GetConversation(convID); err == nil && c != nil {
				agentKey = c.AgentKey
			}

			now := time.Now()
			nextFire := now.Add(time.Duration(a.CooldownMinutes) * time.Minute)
			reason := strings.TrimSpace(a.Reason)
			if reason == "" {
				reason = "Proxy auth-page cooldown interval"
			}

			job := CooldownResumeJob{
				ID:                    fmt.Sprintf("cd-%d", now.UnixNano()),
				TargetType:            targetType,
				ConversationID:        convID,
				TaskID:                taskID,
				AgentKey:              agentKey,
				Domain:                strings.TrimSpace(a.Domain),
				Reason:                reason,
				ResumePrompt:          a.ResumePrompt,
				NextFireUnix:          nextFire.Unix(),
				NextFireISO:           nextFire.UTC().Format(time.RFC3339),
				RepeatIntervalMinutes: a.RepeatIntervalMinutes,
				MaxRuns:               a.MaxRuns,
				RunsCompleted:         0,
				Enabled:               true,
				CreatedAtUnix:         now.Unix(),
			}

			cooldownJobsMu.Lock()
			jobs := s.loadCooldownResumeJobsLocked()
			// Deduplicate: replace any pending job for the same conversation/task + domain
			// so an agent doesn't stack duplicate timers on the same target.
			filtered := make([]CooldownResumeJob, 0, len(jobs)+1)
			for _, ex := range jobs {
				if ex.Enabled && ex.TargetType == job.TargetType &&
					ex.ConversationID == job.ConversationID && ex.TaskID == job.TaskID &&
					strings.EqualFold(ex.Domain, job.Domain) {
					continue
				}
				filtered = append(filtered, ex)
			}
			filtered = append(filtered, job)
			err := s.saveCooldownResumeJobsLocked(filtered)
			cooldownJobsMu.Unlock()
			if err != nil {
				return actool.Errorf("failed to persist cooldown job: " + err.Error()), nil
			}

			log.Printf("[cooldown-cron] Scheduled %s resume job %s (domain=%q, in=%dm, repeat=%dm, max_runs=%d)",
				job.TargetType, job.ID, job.Domain, a.CooldownMinutes, a.RepeatIntervalMinutes, a.MaxRuns)

			return jsonResult(map[string]any{
				"ok":           true,
				"job":          job,
				"instructions": fmt.Sprintf("Cooldown continuation %s is persisted and will automatically wake this %s at %s (%d minutes from now). Stop auth-page requests for this domain now and wrap up your current turn cleanly.", job.ID, job.TargetType, job.NextFireISO, a.CooldownMinutes),
			})
		})
}

func (s *Server) toolListCooldownSchedules() actool.CoreTool {
	return roTool("list_cooldown_schedules",
		"List active and recently completed cooldown/cron continuation schedules registered via schedule_cooldown_resume.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			cooldownJobsMu.Lock()
			jobs := s.loadCooldownResumeJobsLocked()
			cooldownJobsMu.Unlock()
			if jobs == nil {
				jobs = []CooldownResumeJob{}
			}
			return jsonResult(map[string]any{
				"count": len(jobs),
				"jobs":  jobs,
			})
		})
}

func (s *Server) toolCancelCooldownSchedule() actool.CoreTool {
	return wrTool("cancel_cooldown_schedule",
		"Cancel a pending cooldown/cron continuation job by job_id (e.g. once valid credentials were found and remaining scheduled waves are no longer needed).",
		objSchema(map[string]any{
			"job_id": strParam("Cooldown job ID returned by schedule_cooldown_resume (e.g. 'cd-...')"),
		}, "job_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				JobID string `json:"job_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := strings.TrimSpace(a.JobID)
			if id == "" {
				return actool.Errorf("job_id is required"), nil
			}
			cooldownJobsMu.Lock()
			jobs := s.loadCooldownResumeJobsLocked()
			removed := false
			kept := make([]CooldownResumeJob, 0, len(jobs))
			for _, j := range jobs {
				if j.ID == id {
					removed = true
					continue
				}
				kept = append(kept, j)
			}
			if removed {
				_ = s.saveCooldownResumeJobsLocked(kept)
			}
			cooldownJobsMu.Unlock()
			return jsonResult(map[string]any{"ok": removed, "job_id": id})
		})
}

// fireCooldownResumes checks persisted cooldown/cron continuation jobs on each
// Scheduler tick and automatically wakes due Conversations or Tasks.
func (sc *Scheduler) fireCooldownResumes() {
	if sc == nil || sc.s == nil || sc.pg == nil {
		return
	}
	now := time.Now()
	nowUnix := now.Unix()

	cooldownJobsMu.Lock()
	jobs := sc.s.loadCooldownResumeJobsLocked()
	if len(jobs) == 0 {
		cooldownJobsMu.Unlock()
		return
	}

	type dueDispatch struct {
		job CooldownResumeJob
	}
	var dispatches []dueDispatch
	changed := false
	updated := make([]CooldownResumeJob, 0, len(jobs))

	for _, j := range jobs {
		if !j.Enabled {
			// Prune disabled/completed entries older than 24h so settings stay compact.
			if nowUnix-j.CreatedAtUnix < 86400 {
				updated = append(updated, j)
			} else {
				changed = true
			}
			continue
		}
		if nowUnix < j.NextFireUnix {
			updated = append(updated, j)
			continue
		}

		// If target conversation is still busy running an active turn, defer firing by 30s.
		if j.TargetType == "conversation" && j.ConversationID > 0 {
			busyKey := sc.s.convBusyKey(j.ConversationID)
			sc.s.chatMu.Lock()
			busy := sc.s.chatBusy[busyKey]
			sc.s.chatMu.Unlock()
			if busy {
				j.NextFireUnix = nowUnix + 30
				j.NextFireISO = time.Unix(j.NextFireUnix, 0).UTC().Format(time.RFC3339)
				changed = true
				updated = append(updated, j)
				continue
			}
		}

		j.RunsCompleted++
		j.LastFiredUnix = nowUnix
		dispatches = append(dispatches, dueDispatch{job: j})
		if j.RepeatIntervalMinutes > 0 && j.RunsCompleted < j.MaxRuns {
			j.NextFireUnix = now.Add(time.Duration(j.RepeatIntervalMinutes) * time.Minute).Unix()
			j.NextFireISO = time.Unix(j.NextFireUnix, 0).UTC().Format(time.RFC3339)
		} else {
			j.Enabled = false
		}
		changed = true
		updated = append(updated, j)
	}

	if changed {
		_ = sc.s.saveCooldownResumeJobsLocked(updated)
	}
	cooldownJobsMu.Unlock()

	for _, d := range dispatches {
		sc.s.dispatchCooldownResumeJob(d.job)
	}
}

func (s *Server) dispatchCooldownResumeJob(j CooldownResumeJob) {
	waveNote := fmt.Sprintf("[Scheduled Cooldown Continuation %s · Wave %d/%d]", j.ID, j.RunsCompleted, max(1, j.MaxRuns))
	if j.Domain != "" {
		waveNote += fmt.Sprintf(" (Target: %s)", j.Domain)
	}
	fullMsg := fmt.Sprintf("%s\nReason: %s\n\nCooldown window has elapsed. Check `check_proxy_status` first, respect commercial proxy auth-page rate limits (<=5 credential attempts/hour spaced >=10s apart unless using `scraped-*` proxies or Tor), and execute the next planned batch:\n\n%s\n\n(If valid access is achieved and further scheduled waves are unnecessary, call `cancel_cooldown_schedule(job_id=%q)`.)",
		waveNote, j.Reason, j.ResumePrompt, j.ID)

	if j.TargetType == "task" && j.TaskID > 0 {
		t := s.m.ResolveTask(strconv.FormatInt(j.TaskID, 10))
		if t == nil {
			log.Printf("[cooldown-cron] Task #%d no longer exists; skipping job %s", j.TaskID, j.ID)
			return
		}
		hintPayload, _ := json.Marshal(map[string]any{
			"task_id": t.ID,
			"text":    fullMsg,
		})
		_, _ = s.toolAddHint().Call(context.Background(), hintPayload, nil)
		s.reviveTask(t)
		log.Printf("[cooldown-cron] Woke Task #%d for cooldown continuation %s (wave %d/%d)", j.TaskID, j.ID, j.RunsCompleted, j.MaxRuns)
		return
	}

	if j.ConversationID > 0 {
		conv, err := s.m.pg.GetConversation(j.ConversationID)
		if err != nil || conv == nil {
			log.Printf("[cooldown-cron] Conversation #%d no longer exists; skipping job %s", j.ConversationID, j.ID)
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

		act := db.Activity{
			Worker:  "user",
			Kind:    "user",
			Summary: waveNote,
			Detail:  fullMsg,
		}
		ua, aerr := s.m.pg.AppendConvActivity(conv.ID, act)
		if aerr == nil {
			act.ID = ua
			act.CreatedAt = time.Now()
			globalConvStreamHub.publish(conv.ID, "activity", activityDTO(act))
		}
		globalConvStreamHub.publish(conv.ID, "status", map[string]any{"running": true})
		log.Printf("[cooldown-cron] Woke Conversation #%d (%s) for cooldown continuation %s (wave %d/%d)",
			conv.ID, conv.AgentKey, j.ID, j.RunsCompleted, j.MaxRuns)
		s.runConversation(conv, fullMsg, busyKey)
	}
}
