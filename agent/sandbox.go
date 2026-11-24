package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
}

// SandboxConfigFromEnv reads the sandbox settings from the environment, with
// safe defaults. env: BEHEMOTH_SANDBOX_IMAGE, BEHEMOTH_SANDBOX_NETWORK,
// BEHEMOTH_SANDBOX_TIMEOUT (seconds), BEHEMOTH_SANDBOX_ARGS (space-separated).
func SandboxConfigFromEnv(workDir string) SandboxConfig {
	cfg := SandboxConfig{
		Image:   strings.TrimSpace(os.Getenv("BEHEMOTH_SANDBOX_IMAGE")),
		Network: strings.TrimSpace(os.Getenv("BEHEMOTH_SANDBOX_NETWORK")),
		Timeout: 10 * time.Minute,
		WorkDir: workDir,
	}
	if cfg.Image == "" {
		cfg.Image = "kalilinux/kali-last-release"
	}
	if cfg.Network == "" {
		cfg.Network = "host"
	}
	if v := strings.TrimSpace(os.Getenv("BEHEMOTH_SANDBOX_TIMEOUT")); v != "" {
		if secs, err := time.ParseDuration(v + "s"); err == nil && secs > 0 {
			cfg.Timeout = secs
		}
	}
	if v := strings.TrimSpace(os.Getenv("BEHEMOTH_SANDBOX_ARGS")); v != "" {
		cfg.ExtraArgs = strings.Fields(v)
	}
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
	args = append(args, c.ExtraArgs...)
	args = append(args, image, "sh", "-lc", command)
	return args
}

// SandboxExecTool builds the sandbox_exec tool. The tool is always registered so
// the model can learn the sandbox exists; calls fail with a usable message when
// docker is missing.
func SandboxExecTool(cfg SandboxConfig) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "sandbox_exec",
		Description: "Run ONE command inside a throwaway Docker container (image " + cfg.Image +
			", network " + cfg.Network + "), with the workspace mounted at /work. " +
			"Use it for heavyweight or risky tooling so the host is untouched; use Bash for quick local work, " +
			"and shell_open for interactive programs. The container is removed after the run.",
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
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return runSandboxExec(ctx, cfg, in), nil
		},
	})
}

func runSandboxExec(ctx context.Context, cfg SandboxConfig, in json.RawMessage) actool.Result {
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

	cmd := exec.CommandContext(runCtx, "docker", cfg.dockerArgs(args.Command)...)
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
