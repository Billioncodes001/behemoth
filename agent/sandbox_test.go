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
	t.Setenv("BEHEMOTH_SANDBOX_IMAGE", "")
	t.Setenv("BEHEMOTH_SANDBOX_NETWORK", "")
	t.Setenv("BEHEMOTH_SANDBOX_TIMEOUT", "")
	t.Setenv("BEHEMOTH_SANDBOX_ARGS", "")
	t.Setenv("BEHEMOTH_SANDBOX_GPUS", "")
	cfg := SandboxConfigFromEnv("/tmp/work")
	if cfg.Image != "kalilinux/kali-last-release" || cfg.Network != "host" || cfg.WorkDir != "/tmp/work" {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.Timeout != 10*time.Minute {
		t.Fatalf("timeout = %s; want 10m", cfg.Timeout)
	}
	if cfg.GPUs != "" {
		t.Fatalf("gpus = %q; want empty (CPU-only host)", cfg.GPUs)
	}
}

func TestSandboxConfigFromEnvOverrides(t *testing.T) {
	t.Setenv("BEHEMOTH_SANDBOX_IMAGE", "my/kali:latest")
	t.Setenv("BEHEMOTH_SANDBOX_NETWORK", "none")
	t.Setenv("BEHEMOTH_SANDBOX_TIMEOUT", "45")
	t.Setenv("BEHEMOTH_SANDBOX_ARGS", "--cap-add=NET_RAW --memory=1g")
	t.Setenv("BEHEMOTH_SANDBOX_GPUS", "all")
	cfg := SandboxConfigFromEnv("/work")
	if cfg.Image != "my/kali:latest" || cfg.Network != "none" || cfg.Timeout != 45*time.Second {
		t.Fatalf("config = %+v", cfg)
	}
	if len(cfg.ExtraArgs) != 2 || cfg.ExtraArgs[0] != "--cap-add=NET_RAW" {
		t.Fatalf("extra args = %v", cfg.ExtraArgs)
	}
	if cfg.GPUs != "all" {
		t.Fatalf("gpus = %q; want all", cfg.GPUs)
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
	if strings.Contains(args, "--gpus") {
		t.Fatalf("docker args %q should not request GPUs when unset", args)
	}
}

// A configured GPU passthrough must reach docker before the image name, so the
// flag is a run option and not part of the command.
func TestSandboxDockerArgsGPUs(t *testing.T) {
	cfg := SandboxConfig{Image: "img:1", Network: "host", WorkDir: "/data/run", GPUs: "all"}
	args := cfg.dockerArgs("hashcat -b")
	if got := strings.Join(args, " "); !strings.Contains(got, "--gpus all img:1 sh -lc hashcat -b") {
		t.Fatalf("docker args %q missing GPU passthrough before image", got)
	}
}

func TestSandboxDockerArgsForwardsProxyAndMountsMITMCACert(t *testing.T) {
	caFile := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(caFile, []byte("FAKE-CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgHost := SandboxConfig{Image: "img:1", Network: "host", WorkDir: "/data/run"}
	env := []string{
		"HTTP_PROXY=http://127.0.0.1:8788",
		"HTTPS_PROXY=http://127.0.0.1:8788",
		"NO_PROXY=localhost,127.0.0.1",
		"SSL_CERT_FILE=" + caFile,
	}
	gotHost := strings.Join(cfgHost.dockerArgsWithEnv("curl -I https://example.com", env), " ")
	for _, want := range []string{
		"-v " + caFile + ":" + sandboxContainerCACertPath + ":ro",
		"-e SSL_CERT_FILE=" + sandboxContainerCACertPath,
		"-e REQUESTS_CA_BUNDLE=" + sandboxContainerCACertPath,
		"-e HTTP_PROXY=http://127.0.0.1:8788",
	} {
		if !strings.Contains(gotHost, want) {
			t.Fatalf("host network args %q missing %q", gotHost, want)
		}
	}

	cfgBridge := SandboxConfig{Image: "img:1", Network: "bridge", WorkDir: "/data/run"}
	gotBridge := strings.Join(cfgBridge.dockerArgsWithEnv("curl -I https://example.com", env), " ")
	for _, want := range []string{
		"--add-host=host.docker.internal:host-gateway",
		"-e HTTP_PROXY=http://host.docker.internal:8788",
	} {
		if !strings.Contains(gotBridge, want) {
			t.Fatalf("bridge network args %q missing %q", gotBridge, want)
		}
	}
}

// End-to-end container run. Opt-in (BEHEMOTH_SANDBOX_TEST=1) because it needs a
// docker daemon and may pull an image.
func TestSandboxExecOptional(t *testing.T) {
	if testing.Short() || strings.TrimSpace(os.Getenv("BEHEMOTH_SANDBOX_TEST")) != "1" {
		t.Skip("set BEHEMOTH_SANDBOX_TEST=1 to run the docker end-to-end test")
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
