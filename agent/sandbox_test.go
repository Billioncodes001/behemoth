package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSandboxConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("ARTEX_SANDBOX_IMAGE", "")
	t.Setenv("ARTEX_SANDBOX_NETWORK", "")
	t.Setenv("ARTEX_SANDBOX_TIMEOUT", "")
	t.Setenv("ARTEX_SANDBOX_ARGS", "")
	cfg := SandboxConfigFromEnv("/tmp/work")
	if cfg.Image != "kalilinux/kali-last-release" || cfg.Network != "host" || cfg.WorkDir != "/tmp/work" {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.Timeout != 10*time.Minute {
		t.Fatalf("timeout = %s; want 10m", cfg.Timeout)
	}
}

func TestSandboxConfigFromEnvOverrides(t *testing.T) {
	t.Setenv("ARTEX_SANDBOX_IMAGE", "my/kali:latest")
	t.Setenv("ARTEX_SANDBOX_NETWORK", "none")
	t.Setenv("ARTEX_SANDBOX_TIMEOUT", "45")
	t.Setenv("ARTEX_SANDBOX_ARGS", "--cap-add=NET_RAW --memory=1g")
	cfg := SandboxConfigFromEnv("/work")
	if cfg.Image != "my/kali:latest" || cfg.Network != "none" || cfg.Timeout != 45*time.Second {
		t.Fatalf("config = %+v", cfg)
	}
	if len(cfg.ExtraArgs) != 2 || cfg.ExtraArgs[0] != "--cap-add=NET_RAW" {
		t.Fatalf("extra args = %v", cfg.ExtraArgs)
	}
}

// The docker invocation must mount the workspace, pin the network mode and pass
// the command through sh -lc so shell syntax works.
func TestSandboxDockerArgs(t *testing.T) {
	cfg := SandboxConfig{Image: "img:1", Network: "bridge", WorkDir: "/data/run", ExtraArgs: []string{"--cap-add=NET_RAW"}}
	args := strings.Join(cfg.dockerArgs("nmap -sV 127.0.0.1"), " ")
	for _, want := range []string{"run --rm -i", "--network=bridge", "-v /data/run:/work", "-w /work", "-e HOME=/work", "--cap-add=NET_RAW", "img:1 sh -lc nmap -sV 127.0.0.1"} {
		if !strings.Contains(args, want) {
			t.Fatalf("docker args %q missing %q", args, want)
		}
	}
}

// End-to-end container run. Opt-in (ARTEX_SANDBOX_TEST=1) because it needs a
// docker daemon and may pull an image.
func TestSandboxExecOptional(t *testing.T) {
	if testing.Short() || strings.TrimSpace(os.Getenv("ARTEX_SANDBOX_TEST")) != "1" {
		t.Skip("set ARTEX_SANDBOX_TEST=1 to run the docker end-to-end test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	cfg := SandboxConfigFromEnv(t.TempDir())
	cfg.Image = "alpine:3.20"
	cfg.Network = "none"
	cfg.Timeout = 2 * time.Minute
	tool := SandboxExecTool(cfg)
	res, err := tool.Call(context.Background(), json.RawMessage(`{"command":"echo sandbox-ok"}`), nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.IsError || !strings.Contains(blocksText(res.Content), "sandbox-ok") {
		t.Fatalf("result = %s", blocksText(res.Content))
	}
}
