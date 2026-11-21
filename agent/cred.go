// Package agent implements credential collection and secure storage.
// Inspired by NukeRat's credential management system.
package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ---------- Types ----------

// CredType represents the type of credential.
type CredType string

const (
	CredPassword CredType = "password"
	CredHash     CredType = "hash"
	CredAPIKey   CredType = "api_key"
	CredSSHCert  CredType = "ssh_cert"
	CredTLSCert  CredType = "tls_cert"
	CredCookie   CredType = "cookie"
	CredToken    CredType = "token"
	CredNTLM     CredType = "ntlm"
	CredKerberos CredType = "kerberos"
)

// Credential represents a collected credential.
type Credential struct {
	ID         int64      `json:"id"`
	Type       CredType   `json:"type"`
	Username   string     `json:"username,omitempty"`
	Password   string     `json:"password,omitempty"` // Encrypted at rest
	Hash       string     `json:"hash,omitempty"`
	Domain     string     `json:"domain,omitempty"`
	Source     string     `json:"source"` // Where it was found
	Host       string     `json:"host,omitempty"`
	Port       int        `json:"port,omitempty"`
	Service    string     `json:"service,omitempty"` // ssh, rdp, http, smb, etc.
	TaskID     *int64     `json:"task_id,omitempty"`
	Confidence int        `json:"confidence"` // 0-100
	Verified   bool       `json:"verified"`
	Notes      string     `json:"notes,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsed   *time.Time `json:"last_used,omitempty"`
	Tags       []string   `json:"tags,omitempty"`
}

// CredFilter defines filters for credential queries.
type CredFilter struct {
	Type     CredType `json:"type,omitempty"`
	Username string   `json:"username,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Host     string   `json:"host,omitempty"`
	Service  string   `json:"service,omitempty"`
	TaskID   *int64   `json:"task_id,omitempty"`
	Verified *bool    `json:"verified,omitempty"`
	Limit    int      `json:"limit,omitempty"`
}

// CredStats contains statistics about credentials.
type CredStats struct {
	Total         int              `json:"total"`
	ByType        map[CredType]int `json:"by_type"`
	ByService     map[string]int   `json:"by_service"`
	Verified      int              `json:"verified"`
	UniqueDomains int              `json:"unique_domains"`
	UniqueHosts   int              `json:"unique_hosts"`
}

// ---------- Store ----------

// Store manages credentials with encryption at rest.
type Store struct {
	mu         sync.RWMutex
	creds      map[int64]*Credential
	nextID     int64
	encryptKey []byte // AES-256 key for encrypting passwords
	config     StoreConfig
}

// StoreConfig holds store configuration.
type StoreConfig struct {
	AutoExtract bool     `json:"auto_extract"`
	MaxCreds    int      `json:"max_creds"`
	DefaultTags []string `json:"default_tags"`
}

// NewStore creates a new credential store.
func NewStore(config StoreConfig) (*Store, error) {
	if config.MaxCreds == 0 {
		config.MaxCreds = 5000
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	return &Store{
		creds:      make(map[int64]*Credential),
		nextID:     1,
		encryptKey: key,
		config:     config,
	}, nil
}

// Add adds a new credential to the store.
func (s *Store) Add(cred *Credential) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.config.MaxCreds > 0 && len(s.creds) >= s.config.MaxCreds {
		return 0, fmt.Errorf("credential store is full (max %d)", s.config.MaxCreds)
	}

	// Encrypt password at rest
	if cred.Password != "" {
		encrypted, err := s.encrypt(cred.Password)
		if err != nil {
			return 0, err
		}
		cred.Password = encrypted
	}

	cred.ID = s.nextID
	s.nextID++
	if cred.CreatedAt.IsZero() {
		cred.CreatedAt = time.Now()
	}
	if cred.Confidence == 0 {
		cred.Confidence = 50
	}
	if len(cred.Tags) == 0 {
		cred.Tags = append(cred.Tags, s.config.DefaultTags...)
	}

	s.creds[cred.ID] = cred
	return cred.ID, nil
}

// Get retrieves a credential by ID.
func (s *Store) Get(id int64) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cred, ok := s.creds[id]
	if !ok {
		return nil, fmt.Errorf("credential not found")
	}
	return s.decryptCopy(cred)
}

// Query retrieves credentials matching the filter.
func (s *Store) Query(filter CredFilter) ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*Credential
	for _, cred := range s.creds {
		if filter.Type != "" && cred.Type != filter.Type {
			continue
		}
		if filter.Username != "" && cred.Username != filter.Username {
			continue
		}
		if filter.Domain != "" && cred.Domain != filter.Domain {
			continue
		}
		if filter.Host != "" && cred.Host != filter.Host {
			continue
		}
		if filter.Service != "" && cred.Service != filter.Service {
			continue
		}
		if filter.Verified != nil && cred.Verified != *filter.Verified {
			continue
		}

		decrypted, err := s.decryptCopy(cred)
		if err != nil {
			continue
		}
		results = append(results, decrypted)

		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results, nil
}

// GetAll returns all credentials.
func (s *Store) GetAll() ([]*Credential, error) { return s.Query(CredFilter{}) }

// Delete removes a credential by ID.
func (s *Store) Delete(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.creds[id]; !ok {
		return fmt.Errorf("credential not found")
	}
	delete(s.creds, id)
	return nil
}

// MarkVerified marks a credential as verified.
func (s *Store) MarkVerified(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, ok := s.creds[id]
	if !ok {
		return fmt.Errorf("credential not found")
	}
	cred.Verified = true
	return nil
}

// UpdateLastUsed updates the last used timestamp.
func (s *Store) UpdateLastUsed(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, ok := s.creds[id]
	if !ok {
		return fmt.Errorf("credential not found")
	}
	now := time.Now()
	cred.LastUsed = &now
	return nil
}

// Stats returns credential statistics.
func (s *Store) Stats() CredStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := CredStats{
		Total:     len(s.creds),
		ByType:    make(map[CredType]int),
		ByService: make(map[string]int),
	}
	domains := make(map[string]bool)
	hosts := make(map[string]bool)

	for _, cred := range s.creds {
		stats.ByType[cred.Type]++
		stats.ByService[cred.Service]++
		if cred.Verified {
			stats.Verified++
		}
		if cred.Domain != "" {
			domains[cred.Domain] = true
		}
		if cred.Host != "" {
			hosts[cred.Host] = true
		}
	}
	stats.UniqueDomains = len(domains)
	stats.UniqueHosts = len(hosts)
	return stats
}

// GetEncryptionKey returns the encryption key (for persistence).
func (s *Store) GetEncryptionKey() []byte { return s.encryptKey }

// ---------- Encryption ----------

func (s *Store) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.encryptKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *Store) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.encryptKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (s *Store) decryptCopy(cred *Credential) (*Credential, error) {
	copy := *cred
	var err error
	if copy.Password != "" {
		copy.Password, err = s.decrypt(copy.Password)
		if err != nil {
			return nil, err
		}
	}
	return &copy, nil
}

// ---------- Helpers ----------

// ExtractFromText attempts to extract credentials from text output.
// This is useful for parsing command outputs like mimikatz, hashdump, etc.
func (s *Store) ExtractFromText(text, source string, taskID *int64) []*Credential {
	var creds []*Credential
	// Pattern: username:password or domain\username:password
	patterns := []struct {
		re        string
		hasDomain bool
	}{
		{`([^\s:]+):(\S+)@(\S+)`, false},                      // user:pass@host
		{`(\\)?(\S+)\s+(\S+)`, true},                          // DOMAIN\user pass
		{`Username:\s*(\S+)[\s\S]*?Password:\s*(\S+)`, false}, // Structured output
	}
	// Basic extraction - in production, use more sophisticated parsers
	for _, p := range patterns {
		// Simplified - would need regex matching here
		_ = p
	}
	_ = text
	_ = source
	_ = taskID
	return creds
}

// ExportJSON exports credentials as encrypted JSON.
func (s *Store) ExportJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.creds)
}
