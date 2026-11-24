package c2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestBuildImplantDefaults(t *testing.T) {
	m := newTestManager(t)
	im, err := m.BuildImplant(BuildOpts{})
	if err != nil {
		t.Fatalf("BuildImplant: %v", err)
	}
	if im.Platform != "linux" || im.Runtime != "bash" || im.Encrypt != "none" {
		t.Fatalf("unexpected defaults: %+v", im)
	}
	if im.BeaconPath != "update" || im.RespPath != "response" {
		t.Fatalf("profile defaults: %s / %s", im.BeaconPath, im.RespPath)
	}
	if im.SleepSeconds != 30 || im.JitterPct != 20 {
		t.Fatalf("sleep defaults: %d/%d", im.SleepSeconds, im.JitterPct)
	}
	if !strings.HasPrefix(im.ID, "c2_") || len(im.Token) < 32 {
		t.Fatalf("id/token shape: %s %s", im.ID, im.Token)
	}
	if _, err := os.Stat(filepath.Join(m.BuildDir(im.ID), "implant.sh")); err != nil {
		t.Fatalf("implant.sh missing: %v", err)
	}
	for _, f := range []string{"install-none.sh", "install-systemd.sh", "install-cron.sh", "README.txt"} {
		if _, err := os.Stat(filepath.Join(m.BuildDir(im.ID), f)); err != nil {
			t.Fatalf("%s missing: %v", f, err)
		}
	}
}

func TestBuildImplantValidation(t *testing.T) {
	m := newTestManager(t)
	cases := []BuildOpts{
		{Platform: "solaris"},
		{Runtime: "ruby"},
		{Platform: "windows", Runtime: "bash"},
		{Encrypt: "rot13"},
		{Runtime: "python3", Encrypt: "aes"},
		{Persistence: "schtasks"},
		{BeaconPath: "api/c2"},
		{BeaconPath: "api/update", RespPath: "api/update"},
		{BeaconPath: "../etc"},
	}
	for i, o := range cases {
		if _, err := m.BuildImplant(o); err == nil {
			t.Errorf("case %d: expected error for %+v", i, o)
		}
	}
	if _, err := m.BuildImplant(BuildOpts{Platform: "windows", Persistence: "schtasks"}); err != nil {
		t.Errorf("windows build: %v", err)
	}
}

func TestTaskLifecycleAndResults(t *testing.T) {
	m := newTestManager(t)
	im, err := m.BuildImplant(BuildOpts{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := m.AddTask(im.ID, CmdShell, "", 0); err == nil {
		t.Fatal("empty shell args should be rejected")
	}
	task, err := m.AddTask(im.ID, CmdShell, "id", 0)
	if err != nil {
		t.Fatalf("AddTask: %v", err)
	}
	if task.Status != "pending" || task.TimeoutSeconds != defaultTimeout {
		t.Fatalf("task defaults: %+v", task)
	}
	got, ok := m.Dequeue(im.ID)
	if !ok || got.ID != task.ID || got.Status != "sent" {
		t.Fatalf("Dequeue: %+v ok=%v", got, ok)
	}
	if _, ok := m.Dequeue(im.ID); ok {
		t.Fatal("second dequeue should be empty")
	}
	m.AddResult(im.ID, task.ID, "uid=0(root)", "", 0)
	res := m.Results(im.ID, 5)
	if len(res) != 1 || res[0].Output != "uid=0(root)" {
		t.Fatalf("results: %+v", res)
	}
	tasks := m.Tasks(im.ID, 5)
	if len(tasks) != 1 || tasks[0].Status != "done" {
		t.Fatalf("tasks after result: %+v", tasks)
	}
	m.AddResult(im.ID, 9999, "stray", "", 1)
	if len(m.Results(im.ID, 5)) != 2 {
		t.Fatal("stray result dropped")
	}
	if m.PendingCount(im.ID) != 0 {
		t.Fatal("pending count should be 0")
	}
}

func TestKillMarksImplant(t *testing.T) {
	m := newTestManager(t)
	im, _ := m.BuildImplant(BuildOpts{})
	m.Touch(Beacon{ID: im.ID, Host: "h1"}, "1.2.3.4:1")
	if im.Status() == "killed" {
		t.Fatal("not killed yet")
	}
	if _, err := m.AddTask(im.ID, CmdKill, "", 0); err != nil {
		t.Fatalf("kill task: %v", err)
	}
	got, _ := m.Get(im.ID)
	if got.Status() != "killed" {
		t.Fatalf("status after kill: %s", got.Status())
	}
	if _, err := m.AddTask(im.ID, CmdShell, "id", 0); err == nil {
		t.Fatal("tasks for killed implant should fail")
	}
	m.Touch(Beacon{ID: im.ID}, "1.2.3.4:1")
	got, _ = m.Get(im.ID)
	if got.Status() != "killed" {
		t.Fatal("killed implant resurrected")
	}
}

func TestVerifySecret(t *testing.T) {
	m := newTestManager(t)
	im, _ := m.BuildImplant(BuildOpts{})
	if !m.VerifySecret(im.ID, im.Token) {
		t.Fatal("own token rejected")
	}
	if m.VerifySecret(im.ID, "nope") {
		t.Fatal("bad token accepted")
	}
	if m.VerifySecret("c2_missing", im.Token) {
		t.Fatal("unknown implant accepted")
	}
	t.Setenv("BEHEMOTH_C2_SECRET", "shared-secret")
	m2, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m2.Close()
	im2, _ := m2.BuildImplant(BuildOpts{})
	if !m2.VerifySecret(im2.ID, "shared-secret") {
		t.Fatal("fallback secret rejected")
	}
}

func TestStateReplay(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	im, _ := m.BuildImplant(BuildOpts{Label: "persist"})
	task, _ := m.AddTask(im.ID, CmdShell, "whoami", 0)
	m.Dequeue(im.ID)
	m.AddResult(im.ID, task.ID, "root", "", 0)
	tok := m.ConsoleToken()
	_ = m.Close()

	m2, err := NewManager(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer m2.Close()
	got, ok := m2.Get(im.ID)
	if !ok || got.Label != "persist" {
		t.Fatalf("implant not replayed: %+v ok=%v", got, ok)
	}
	if m2.Count() != 1 {
		t.Fatalf("count: %d", m2.Count())
	}
	if m2.ConsoleToken() != tok {
		t.Fatal("console token not persisted")
	}
	res := m2.Results(im.ID, 10)
	if len(res) != 1 || res[0].Output != "root" {
		t.Fatalf("results replayed: %+v", res)
	}
	tasks := m2.Tasks(im.ID, 10)
	if len(tasks) != 1 || tasks[0].Status != "done" {
		t.Fatalf("tasks replayed: %+v", tasks)
	}
}

func TestStatusStaleness(t *testing.T) {
	im := &Implant{SleepSeconds: 30, JitterPct: 20}
	if im.Status() != "registered" {
		t.Fatal("fresh implant should be registered")
	}
	im.LastSeen = time.Now().Add(-time.Hour)
	if im.Status() != "stale" {
		t.Fatal("old check-in should be stale")
	}
	im.LastSeen = time.Now()
	if im.Status() != "active" {
		t.Fatal("recent check-in should be active")
	}
	im.Killed = true
	if im.Status() != "killed" {
		t.Fatal("killed overrides")
	}
	if StaleAfter(30, 20) <= 90*time.Second {
		t.Fatal("stale window too short")
	}
}

func TestProfilePathCollision(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.BuildImplant(BuildOpts{BeaconPath: "c2/ui/x"}); err == nil {
		t.Fatal("c2/ui collision accepted")
	}
	if _, err := m.BuildImplant(BuildOpts{BeaconPath: "api/c2/decoy"}); err == nil {
		t.Fatal("api/c2 collision accepted")
	}
}
