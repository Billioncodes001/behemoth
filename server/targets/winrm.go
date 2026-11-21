package targets

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm"
)

// WinRMConfig holds WinRM connection config.
type WinRMConfig struct {
	Host     string        `json:"host"`
	Port     int           `json:"port"`
	User     string        `json:"user"`
	Password string        `json:"password"`
	UseHTTPS bool          `json:"use_https"`
	Insecure bool          `json:"insecure"`
	Timeout  time.Duration `json:"timeout"`
}

// WinRMConnector implements TargetConnector for Windows via WinRM.
type WinRMConnector struct {
	config    WinRMConfig
	target    *Target
	client    *winrm.Client
	mu        sync.Mutex
	connected bool
}

// NewWinRMConnector creates new WinRM connector.
func NewWinRMConnector(cfg WinRMConfig) (*WinRMConnector, error) {
	if cfg.Port == 0 {
		cfg.Port = 5985
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &WinRMConnector{
		config: cfg,
		target: &Target{Host: cfg.Host, Port: cfg.Port, User: cfg.User, Type: "winrm"},
	}, nil
}

// Connect establishes WinRM connection.
func (c *WinRMConnector) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connected {
		return nil
	}

	endpoint := winrm.NewEndpoint(
		c.config.Host,
		c.config.Port,
		c.config.UseHTTPS,
		c.config.Insecure,
		nil,
		nil,
		nil,
		c.config.Timeout,
	)

	client, err := winrm.NewClientWithParameters(
		endpoint,
		c.config.User,
		c.config.Password,
		winrm.NewParameters("protocolVersion2", "negotiate", int(c.config.Timeout.Seconds())),
	)
	if err != nil {
		return fmt.Errorf("winrm client: %w", err)
	}

	c.client = client
	c.connected = true
	log.Printf("[winrm] Connected to %s@%s:%d", c.config.User, c.config.Host, c.config.Port)
	return nil
}

// Execute runs command on remote Windows target.
func (c *WinRMConnector) Execute(ctx context.Context, cmd string) (*ExecResult, error) {
	c.mu.Lock()
	if !c.connected || c.client == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("not connected")
	}
	client := c.client
	c.mu.Unlock()

	start := time.Now()
	var stdout, stderr strings.Builder

	exitCode, err := client.RunWithContext(ctx, cmd, &stdout, &stderr)

	result := &ExecResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}
	if err != nil {
		result.Error = err
	}
	return result, nil
}

// Close closes WinRM connection.
func (c *WinRMConnector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.client = nil
	c.connected = false
	return nil
}

// IsConnected returns status.
func (c *WinRMConnector) IsConnected() bool { return c.connected }

// Target returns target info.
func (c *WinRMConnector) Target() *Target { return c.target }
