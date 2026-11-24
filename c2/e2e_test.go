package c2

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	if _, err := m.AddTask(im.ID, CmdShell, "echo behemoth-e2e-ok", 20); err != nil {
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
			if out != "behemoth-e2e-ok\n" && out != "behemoth-e2e-ok" {
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

// runTunnelE2E starts a real implant, opens a pivot tunnel to a local HTTP
// target and asserts a full SOCKS5 request survives the relay.
func runTunnelE2E(t *testing.T, o BuildOpts, argv []string, need []string) {
	t.Helper()
	for _, bin := range need {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	var got atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		_, _ = w.Write([]byte("tunnel-e2e-ok"))
	}))
	defer target.Close()

	m, mux := newTestMux(t)
	api := httptest.NewServer(mux)
	defer api.Close()
	o.BaseURL = api.URL
	o.SleepSeconds = 1
	o.JitterPct = 1
	im, err := m.BuildImplant(o)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	script := filepath.Join(m.BuildDir(im.ID), implantFileName(im.Runtime))
	args := append(append([]string{}, argv...), script)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
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

	tgt := strings.TrimPrefix(target.URL, "http://")
	tun, err := m.TunnelMgr().OpenTunnel(TunnelOpts{ImplantID: im.ID, Target: tgt, Auth: true})
	if err != nil {
		t.Fatalf("open tunnel: %v", err)
	}
	defer m.TunnelMgr().CloseTunnel(tun.ID)

	c, code := socksDial(t, tun.Addr, tun.User, tun.Pass, tgt)
	if code != socksRepOK {
		t.Fatalf("socks reply %d", code)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(25 * time.Second))
	if _, err := c.Write([]byte("GET /t HTTP/1.1\r\nHost: " + tgt + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, err := io.ReadAll(c)
	if err != nil && len(body) == 0 {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "tunnel-e2e-ok") {
		info, _ := m.TunnelMgr().GetTunnel(tun.ID)
		t.Fatalf("relay body %q (target hits=%d, tunnel=%+v)", body, got.Load(), info)
	}
}

func TestBashImplantTunnelE2E(t *testing.T) {
	runTunnelE2E(t, BuildOpts{}, []string{"bash"}, []string{"bash", "curl", "base64", "od"})
}

func TestPythonImplantTunnelE2E(t *testing.T) {
	runTunnelE2E(t, BuildOpts{Runtime: "python3"}, []string{"python3"}, []string{"python3"})
}
