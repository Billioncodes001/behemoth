package tools

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"
)

// ExecutionResult represents the result of a tool execution.
type ExecutionResult struct {
	ID        string        `json:"id"`
	ToolID    string        `json:"tool_id"`
	ToolName  string        `json:"tool_name"`
	Status    string        `json:"status"` // running, completed, failed, timeout
	Command   string        `json:"command"`
	Args      []string      `json:"args"`
	Output    string        `json:"output"`
	Error     string        `json:"error,omitempty"`
	ExitCode  int           `json:"exit_code"`
	Duration  time.Duration `json:"duration"`
	Parsed    interface{}   `json:"parsed,omitempty"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
}

// ExecutorConfig holds executor configuration.
type ExecutorConfig struct {
	MaxConcurrent  int           `json:"max_concurrent"`
	DefaultTimeout time.Duration `json:"default_timeout"`
	MaxOutputSize  int64         `json:"max_output_size"`
	WorkingDir     string        `json:"working_dir"`
}

// DefaultExecutorConfig returns sensible defaults.
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		MaxConcurrent:  5,
		DefaultTimeout: 10 * time.Minute,
		MaxOutputSize:  10 * 1024 * 1024,
		WorkingDir:     "/tmp/artex-tools",
	}
}

// ToolExecutor executes security tools safely.
type ToolExecutor struct {
	config        ExecutorConfig
	catalog       *Catalog
	envProvider   func() []string
	proxyProvider func() string
	mu            sync.Mutex
	running       map[string]*ExecutionResult
	sem           chan struct{}
	history       []*ExecutionResult
}

func (e *ToolExecutor) SetEnvProvider(fn func() []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.envProvider = fn
}

func (e *ToolExecutor) SetProxyProvider(fn func() string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.proxyProvider = fn
}

// injectScannerProxyArgs appends native CLI proxy flags for security scanners that
// otherwise ignore HTTP_PROXY environment variables (such as sqlmap, nmap, gobuster,
// ffuf, nuclei, httpx, nikto, and subfinder) so server IPs are never leaked.
func injectScannerProxyArgs(command string, args []string, proxyURL string) []string {
	px := strings.TrimSpace(proxyURL)
	if px == "" {
		return args
	}
	joined := " " + strings.ToLower(strings.Join(args, " ")) + " "
	if strings.Contains(joined, " --proxy") || strings.Contains(joined, " -proxy ") ||
		strings.Contains(joined, " -x ") || strings.Contains(joined, " -http-proxy ") ||
		strings.Contains(joined, " -useproxy ") {
		return args
	}
	base := strings.ToLower(filepath.Base(command))
	switch base {
	case "sqlmap":
		return append(args, "--proxy="+px)
	case "nuclei", "subfinder":
		return append(args, "-proxy", px)
	case "httpx", "httpx-pd":
		return append(args, "-http-proxy", px)
	case "ffuf":
		return append(args, "-x", px)
	case "gobuster":
		return append(args, "--proxy", px)
	case "nikto":
		return append(args, "-useproxy", px)
	case "nmap":
		// Raw SYN (-sS) bypasses HTTP/SOCKS proxies at OS level; enforce TCP Connect (-sT -Pn --proxies)
		out := make([]string, 0, len(args)+4)
		for _, a := range args {
			if a == "-sS" || a == "-O" {
				continue
			}
			out = append(out, a)
		}
		return append(out, "-sT", "-Pn", "--proxies", px)
	default:
		return args
	}
}

// NewToolExecutor creates a new tool executor.
func NewToolExecutor(catalog *Catalog, cfg ExecutorConfig) *ToolExecutor {
	if cfg.MaxConcurrent <= 0 {
		cfg = DefaultExecutorConfig()
	}
	return &ToolExecutor{
		config:  cfg,
		catalog: catalog,
		running: make(map[string]*ExecutionResult),
		sem:     make(chan struct{}, cfg.MaxConcurrent),
		history: make([]*ExecutionResult, 0),
	}
}

// Execute runs a tool with given parameters.
func (e *ToolExecutor) Execute(ctx context.Context, toolID string, params map[string]string) (*ExecutionResult, error) {
	tool, ok := e.catalog.Get(toolID)
	if !ok {
		return nil, fmt.Errorf("tool not found: %s", toolID)
	}

	args, err := e.buildArgs(tool, params)
	if err != nil {
		return nil, fmt.Errorf("build args: %w", err)
	}

	result := &ExecutionResult{
		ID:        fmt.Sprintf("exec-%d", time.Now().UnixNano()),
		ToolID:    toolID,
		ToolName:  tool.Name,
		Status:    "running",
		Command:   tool.Command,
		Args:      args,
		StartedAt: time.Now(),
	}

	e.mu.Lock()
	e.running[result.ID] = result
	e.mu.Unlock()

	select {
	case e.sem <- struct{}{}:
	case <-ctx.Done():
		result.Status = "failed"
		result.Error = "cancelled"
		return result, ctx.Err()
	}
	defer func() { <-e.sem }()

	timeout := tool.Timeout
	if timeout == 0 {
		timeout = e.config.DefaultTimeout
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	e.mu.Lock()
	envFn := e.envProvider
	pxFn := e.proxyProvider
	e.mu.Unlock()
	if pxFn != nil {
		if px := strings.TrimSpace(pxFn()); px != "" {
			args = injectScannerProxyArgs(tool.Command, args, px)
			result.Args = args
		}
	}
	cmd := exec.CommandContext(execCtx, tool.Command, args...)
	if envFn != nil {
		if extra := envFn(); len(extra) > 0 {
			cmd.Env = append(os.Environ(), extra...)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	result.Output = stdout.String()
	if stderr.Len() > 0 {
		result.Output += "\n[STDERR]\n" + stderr.String()
	}
	result.Duration = time.Since(result.StartedAt)
	result.EndedAt = time.Now()

	if err != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			result.Status = "timeout"
			result.Error = "timed out"
		} else {
			result.Status = "failed"
			result.Error = err.Error()
		}
	} else {
		result.Status = "completed"
	}

	e.mu.Lock()
	delete(e.running, result.ID)
	e.history = append(e.history, result)
	if len(e.history) > 1000 {
		e.history = e.history[len(e.history)-1000:]
	}
	e.mu.Unlock()

	log.Printf("[tools] %s (%s) %v", toolID, result.Status, result.Duration)
	return result, nil
}

// GetRunning returns currently running executions.
func (e *ToolExecutor) GetRunning() []*ExecutionResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := make([]*ExecutionResult, 0, len(e.running))
	for _, v := range e.running {
		r = append(r, v)
	}
	return r
}

// GetExecution returns a specific execution by ID.
func (e *ToolExecutor) GetExecution(id string) (*ExecutionResult, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Check running first
	if r, ok := e.running[id]; ok {
		return r, true
	}
	// Check history
	for _, h := range e.history {
		if h.ID == id {
			return h, true
		}
	}
	return nil, false
}

// History returns execution history.
func (e *ToolExecutor) History(limit int) []*ExecutionResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 || limit >= len(e.history) {
		return e.history
	}
	return e.history[len(e.history)-limit:]
}

// boolTrue reports whether a string parameter value represents a truthy boolean.
func boolTrue(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	}
	return false
}

func (e *ToolExecutor) buildArgs(tool *Tool, params map[string]string) ([]string, error) {
	var args []string
	// FixedArgs always come first (e.g. gobuster's required "dir" subcommand).
	args = append(args, tool.FixedArgs...)

	tplVals := make(map[string]string, len(tool.Parameters))
	for _, p := range tool.Parameters {
		val, ok := params[p.Name]
		if !ok {
			if p.Required {
				return nil, fmt.Errorf("missing required param: %s", p.Name)
			}
			if p.Default != nil {
				switch v := p.Default.(type) {
				case string:
					val = v
				default:
					val = fmt.Sprintf("%v", v)
				}
			} else {
				continue
			}
		}
		tplVals[p.Name] = val
		if tool.ArgsTemplate != "" {
			// Free-form template tools (msfconsole -x) consume ALL params inside
			// the rendered template — positional emission would duplicate them.
			continue
		}
		if strings.EqualFold(p.Type, "bool") {
			// Boolean parameters are switches: emit only the flag itself when
			// truthy and nothing when falsy. Never pass the literal word
			// "true"/"false" — several CLIs (nmap -sV, sqlmap --batch) reject it.
			if boolTrue(val) && p.Flag != "" {
				args = append(args, p.Flag)
			} else if !boolTrue(val) && p.Flag == "" && p.Required {
				return nil, fmt.Errorf("param %s must be a truthy boolean", p.Name)
			}
			continue
		}
		if p.Flag != "" {
			args = append(args, p.Flag)
		}
		args = append(args, val)
	}

	// ArgsTemplate renders a single free-form argument (Go template over the
	// resolved params). Used for CLIs whose interface is a command string
	// (e.g. msfconsole -q -x "use ...; set RHOSTS ...; run; exit").
	if tool.ArgsTemplate != "" {
		tmpl, err := template.New(tool.ID).Parse(tool.ArgsTemplate)
		if err != nil {
			return nil, fmt.Errorf("invalid args template: %w", err)
		}
		var sb strings.Builder
		if err := tmpl.Execute(&sb, tplVals); err != nil {
			return nil, fmt.Errorf("render args template: %w", err)
		}
		if s := sb.String(); strings.TrimSpace(s) != "" {
			args = append(args, s)
		}
	}
	return args, nil
}
