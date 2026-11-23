package c2

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// runImplantE2E builds an implant, starts it for real, and asserts a full
// check-in → task → result round trip over HTTP.
func runImplantE2E(t *testing.T, o BuildOpts, argv []string, need []string) {
	t.Helper()
	for _, bin := range need {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	m, mux := newTestMux(t)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	o.BaseURL = srv.URL
	o.SleepSeconds = 1
	o.JitterPct = 1
	im, err := m.BuildImplant(o)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := m.AddTask(im.ID, CmdShell, "echo artex-e2e-ok", 20); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	script := filepath.Join(m.BuildDir(im.ID), implantFileName(im.Runtime))
	args := append(append([]string{}, argv...), script)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "TMPDIR="+t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatalf("start implant: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	deadline := time.Now().Add(18 * time.Second)
	for time.Now().Before(deadline) {
		if res := m.Results(im.ID, 5); len(res) == 1 {
			out := res[0].Output
			if out != "artex-e2e-ok\n" && out != "artex-e2e-ok" {
				t.Fatalf("unexpected output: %q (err %q, exit %d)", out, res[0].Error, res[0].Exit)
			}
			if got, _ := m.Get(im.ID); got.Status() != "active" {
				t.Fatalf("implant not active after check-in: %s", got.Status())
			}
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("implant did not return a result in time (results=%d)", len(m.Results(im.ID, 5)))
}

func TestBashImplantE2EPlain(t *testing.T) {
	runImplantE2E(t, BuildOpts{}, []string{"bash"}, []string{"bash", "curl", "base64", "od"})
}

func TestBashImplantE2EAES(t *testing.T) {
	runImplantE2E(t, BuildOpts{Encrypt: "aes"}, []string{"bash"}, []string{"bash", "curl", "base64", "od", "openssl"})
}

func TestPythonImplantE2E(t *testing.T) {
	runImplantE2E(t, BuildOpts{Runtime: "python3"}, []string{"python3"}, []string{"python3"})
}
