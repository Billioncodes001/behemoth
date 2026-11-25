package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// Docker sandbox backend. Bash runs on the BEHEMOTH host with the server's
// privileges and filesystem; that is convenient and occasionally destructive.
// sandbox_exec runs one command in a throwaway container instead, with the
// workspace bind-mounted at /work, so heavyweight or risky tooling (nmap, sqlmap,
// nuclei, a suspicious binary) never touches the host.
//
// Design: one-shot containers (`docker run --rm`), never long-lived. Interactive
// programs belong in shell_* PTY sessions; this tool is for command → output.

// SandboxConfig configures the container backend.
type SandboxConfig struct {
	// Image defaults to BEHEMOTH_SANDBOX_IMAGE or kalilinux/kali-last-release.
	Image string
	// Network is the docker network mode: "host" (default: target traffic works),
	// "bridge", or "none".
	Network string
	// Timeout bounds one container run.
	Timeout time.Duration
	// WorkDir is the host directory bind-mounted at /work.
	WorkDir string
	// ExtraArgs are appended to `docker run` (e.g. "--cap-add=NET_RAW").
	ExtraArgs []string
	// GPUs requests host GPU passthrough when non-empty, e.g. "all" or
	// "device=0". Requires the NVIDIA container toolkit on the host; empty means
	// no `--gpus` flag at all (CPU-only hosts behave exactly as before).
	GPUs string
}

func envFirstNonEmpty(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// SandboxConfigFromEnv reads the sandbox settings from the environment, with
// safe defaults. env: BEHEMOTH_SANDBOX_IMAGE, BEHEMOTH_SANDBOX_NETWORK,
// BEHEMOTH_SANDBOX_TIMEOUT (seconds), BEHEMOTH_SANDBOX_ARGS (space-separated),
// BEHEMOTH_SANDBOX_GPUS ("all", "device=0", "0,1"). Legacy ARTEX_SANDBOX_*
// variables are honored as fallbacks.
func SandboxConfigFromEnv(workDir string) SandboxConfig {
	cfg := SandboxConfig{
		Image:   envFirstNonEmpty("BEHEMOTH_SANDBOX_IMAGE", "ARTEX_SANDBOX_IMAGE"),
		Network: envFirstNonEmpty("BEHEMOTH_SANDBOX_NETWORK", "ARTEX_SANDBOX_NETWORK"),
		Timeout: 10 * time.Minute,
		WorkDir: workDir,
	}
	if cfg.Image == "" {
		cfg.Image = "kalilinux/kali-last-release"
	}
	if cfg.Network == "" {
		cfg.Network = "host"
	}
	if v := envFirstNonEmpty("BEHEMOTH_SANDBOX_TIMEOUT", "ARTEX_SANDBOX_TIMEOUT"); v != "" {
		if secs, err := time.ParseDuration(v + "s"); err == nil && secs > 0 {
			cfg.Timeout = secs
		}
	}
	if v := envFirstNonEmpty("BEHEMOTH_SANDBOX_ARGS", "ARTEX_SANDBOX_ARGS"); v != "" {
		cfg.ExtraArgs = strings.Fields(v)
	}
	cfg.GPUs = envFirstNonEmpty("BEHEMOTH_SANDBOX_GPUS", "ARTEX_SANDBOX_GPUS")
	return cfg
}

// Available reports whether the docker CLI is on PATH.
func (c SandboxConfig) Available() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// dockerArgs builds the `docker run` argument list for one command. Pure so the
// mapping is unit-testable without a daemon.
func (c SandboxConfig) dockerArgs(command string) []string {
	return c.dockerArgsWithEnv(command, nil)
}

const sandboxContainerCACertPath = "/etc/behemoth-mitm-ca.pem"

func rewriteLoopbackProxyForBridge(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw, false
	}
	h := strings.ToLower(u.Hostname())
	if h != "127.0.0.1" && h != "localhost" && h != "::1" {
		return raw, false
	}
	if port := u.Port(); port != "" {
		u.Host = "host.docker.internal:" + port
	} else {
		u.Host = "host.docker.internal"
	}
	return u.String(), true
}

func (c SandboxConfig) dockerArgsWithEnv(command string, toolEnv []string) []string {
	image := c.Image
	if image == "" {
		image = "kalilinux/kali-last-release"
	}
	network := c.Network
	if network == "" {
		network = "host"
	}
	workdir := c.WorkDir
	if workdir == "" {
		workdir = "."
	}
	args := []string{
		"run", "--rm", "-i",
		"--network=" + network,
		"-v", workdir + ":/work",
		"-w", "/work",
		"-e", "HOME=/work",
	}

	// Forward live proxy & MITM CA environment variables so commands inside the
	// sandbox container honor Proxy Pool, Exclusive Tor, MITM Capture, and the
	// 503 Fail-Closed Proxy Guard instead of leaking the host's real IP.
	var hostCACert string
	needsHostGateway := false
	var extraEnv []string
	for _, kv := range toolEnv {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		switch k {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy":
			if network == "bridge" {
				var bridged bool
				v, bridged = rewriteLoopbackProxyForBridge(v)
				if bridged {
					needsHostGateway = true
				}
			}
			extraEnv = append(extraEnv, k+"="+v)
		case "NO_PROXY", "no_proxy", "NODE_USE_ENV_PROXY", "PIP_BREAK_SYSTEM_PACKAGES":
			extraEnv = append(extraEnv, k+"="+v)
		case "SSL_CERT_FILE":
			if _, err := os.Stat(v); err == nil {
				hostCACert = v
			}
		}
	}
	if needsHostGateway {
		args = append(args, "--add-host=host.docker.internal:host-gateway")
	}
	if hostCACert != "" {
		args = append(args,
			"-v", hostCACert+":"+sandboxContainerCACertPath+":ro",
			"-e", "SSL_CERT_FILE="+sandboxContainerCACertPath,
			"-e", "CURL_CA_BUNDLE="+sandboxContainerCACertPath,
			"-e", "REQUESTS_CA_BUNDLE="+sandboxContainerCACertPath,
			"-e", "GIT_SSL_CAINFO="+sandboxContainerCACertPath,
			"-e", "NODE_EXTRA_CA_CERTS="+sandboxContainerCACertPath,
		)
	}
	for _, e := range extraEnv {
		args = append(args, "-e", e)
	}

	if gpus := strings.TrimSpace(c.GPUs); gpus != "" {
		args = append(args, "--gpus", gpus)
	}
	args = append(args, c.ExtraArgs...)
	args = append(args, image, "sh", "-lc", command)
	return args
}

// SandboxExecTool builds the sandbox_exec tool. The tool is always registered so
// the model can learn the sandbox exists; calls fail with a usable message when
// docker is missing.
func SandboxExecTool(cfg SandboxConfig) actool.CoreTool {
	desc := "Run ONE command inside a throwaway Docker container (image " + cfg.Image +
		", network " + cfg.Network + "), with the workspace mounted at /work. " +
		"Use it for heavyweight or risky tooling so the host is untouched; use Bash for quick local work, " +
		"and shell_open for interactive programs. The container is removed after the run."
	if cfg.GPUs != "" {
		desc += " A host GPU is passed through (docker --gpus " + cfg.GPUs + "), so CUDA/OpenCL cracker builds (hashcat, john-jumbo) work here."
	}
	return actool.Build(actool.Spec{
		Name:        "sandbox_exec",
		Description: desc,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command":         str("Shell command to run inside the container (executed via sh -lc)."),
				"timeout_seconds": intp("Optional per-call timeout in seconds (defaults to the sandbox timeout)."),
			},
			"required": []string{"command"},
		},
		ReadOnly:   func(json.RawMessage) bool { return false },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision {
			return acperm.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var toolEnv []string
			if tc != nil {
				toolEnv = tc.Env
			}
			return runSandboxExec(ctx, cfg, in, toolEnv), nil
		},
	})
}

func runSandboxExec(ctx context.Context, cfg SandboxConfig, in json.RawMessage, toolEnv []string) actool.Result {
	var args struct {
		Command        string `json:"command"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(in, &args); err != nil {
		return actool.Errorf("invalid input: " + err.Error())
	}
	if strings.TrimSpace(args.Command) == "" {
		return actool.Errorf("command is required")
	}
	if !cfg.Available() {
		return actool.Errorf("sandbox_exec unavailable: docker CLI not found on the BEHEMOTH host. Fall back to Bash for this command, or install Docker to enable isolated execution.")
	}
	timeout := cfg.Timeout
	if args.TimeoutSeconds > 0 {
		timeout = time.Duration(args.TimeoutSeconds) * time.Second
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "docker", cfg.dockerArgsWithEnv(args.Command, toolEnv)...)
	started := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(started)
	result := map[string]any{
		"command":    args.Command,
		"image":      cfg.Image,
		"network":    cfg.Network,
		"output":     string(out),
		"elapsed_ms": elapsed.Milliseconds(),
		"timed_out":  errors.Is(runCtx.Err(), context.DeadlineExceeded),
	}
	if cfg.GPUs != "" {
		result["gpus"] = cfg.GPUs
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		result["exit_code"] = 0
	case errors.As(err, &exitErr):
		result["exit_code"] = exitErr.ExitCode()
	case runCtx.Err() == context.DeadlineExceeded:
		result["exit_code"] = -1
		result["error"] = fmt.Sprintf("timed out after %s", timeout)
	default:
		result["exit_code"] = -1
		result["error"] = err.Error()
	}
	body, merr := json.Marshal(result)
	if merr != nil {
		return actool.Errorf(merr.Error())
	}
	if code, _ := result["exit_code"].(int); code != 0 {
		return actool.Errorf(string(body))
	}
	return actool.Text(string(body))
}
