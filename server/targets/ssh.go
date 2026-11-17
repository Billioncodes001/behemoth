package targets

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Target represents a remote target.
type Target struct {
	ID     string   `json:"id"`
	Host   string   `json:"host"`
	Port   int      `json:"port"`
	User   string   `json:"user"`
	Type   string   `json:"type"`
	Labels []string `json:"labels"`
}

// ExecResult represents command execution result.
type ExecResult struct {
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
	Error    error         `json:"-"`
}

// TargetConnector interface for remote interaction.
type TargetConnector interface {
	Connect(ctx context.Context) error
	Execute(ctx context.Context, cmd string) (*ExecResult, error)
	Close() error
	IsConnected() bool
	Target() *Target
}

// SSHConfig holds SSH connection config.
type SSHConfig struct {
	Host     string        `json:"host"`
	Port     int           `json:"port"`
	User     string        `json:"user"`
	Password string        `json:"password,omitempty"`
	KeyPath  string        `json:"key_path,omitempty"`
	Timeout  time.Duration `json:"timeout"`
}

// SSHConnector implements TargetConnector for SSH.
type SSHConnector struct {
	config    SSHConfig
	target    *Target
	client    *ssh.Client
	mu        sync.Mutex
	connected bool
}

// NewSSHConnector creates new SSH connector.
func NewSSHConnector(cfg SSHConfig) (*SSHConnector, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	return &SSHConnector{
		config: cfg,
		target: &Target{Host: cfg.Host, Port: cfg.Port, User: cfg.User, Type: "ssh"},
	}, nil
}

// Connect establishes SSH connection.
func (c *SSHConnector) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connected {
		return nil
	}

	var authMethods []ssh.AuthMethod
	if c.config.Password != "" {
		authMethods = append(authMethods, ssh.Password(c.config.Password))
	}
	if c.config.KeyPath != "" {
		keyData, err := os.ReadFile(c.config.KeyPath)
		if err != nil {
			return fmt.Errorf("read key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return fmt.Errorf("parse key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if len(authMethods) == 0 {
		return fmt.Errorf("no auth method")
	}

	cfg := &ssh.ClientConfig{
		User:            c.config.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	c.client = client
	c.connected = true
	log.Printf("[ssh] Connected to %s@%s:%d", c.config.User, c.config.Host, c.config.Port)
	return nil
}

// Execute runs command on remote target.
func (c *SSHConnector) Execute(ctx context.Context, cmd string) (*ExecResult, error) {
	c.mu.Lock()
	if !c.connected || c.client == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("not connected")
	}
	client := c.client
	c.mu.Unlock()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	defer session.Close()

	var out, errBuf strings.Builder
	session.Stdout = &out
	session.Stderr = &errBuf

	start := time.Now()
	err = session.Run(cmd)

	result := &ExecResult{
		Stdout:   out.String(),
		Stderr:   errBuf.String(),
		Duration: time.Since(start),
	}
	if err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			result.ExitCode = e.ExitStatus()
		} else {
			result.Error = err
		}
	}
	return result, nil
}

// Close closes SSH connection.
func (c *SSHConnector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		err := c.client.Close()
		c.client = nil
		c.connected = false
		return err
	}
	return nil
}

// IsConnected returns status.
func (c *SSHConnector) IsConnected() bool { return c.connected }

// Target returns target info.
func (c *SSHConnector) Target() *Target { return c.target }

// ============================================================
// SFTP SUPPORT
// ============================================================

// SFTPSession wraps SFTP client for file operations.
type SFTPSession struct {
	client *sftp.Client
}

// NewSFTPSession creates new SFTP session from existing SSH connection.
func (c *SSHConnector) NewSFTPSession() (*SFTPSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.connected || c.client == nil {
		return nil, fmt.Errorf("not connected")
	}
	sftpClient, err := sftp.NewClient(c.client)
	if err != nil {
		return nil, fmt.Errorf("sftp client: %w", err)
	}
	return &SFTPSession{client: sftpClient}, nil
}

// UploadFile uploads a local file to remote path.
func (s *SFTPSession) UploadFile(localPath, remotePath string) error {
	srcFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := s.client.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote: %w", err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

// DownloadFile downloads a remote file to local path.
func (s *SFTPSession) DownloadFile(remotePath, localPath string) error {
	srcFile, err := s.client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create local: %w", err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

// ListDir lists directory contents.
func (s *SFTPSession) ListDir(path string) ([]os.FileInfo, error) {
	return s.client.ReadDir(path)
}

// Close closes SFTP session.
func (s *SFTPSession) Close() error {
	return s.client.Close()
}