package factgraph

import (
	"encoding/json"
	"fmt"
	"time"
)

// FactKind defines the type of fact.
type FactKind string

const (
	FactHost    FactKind = "host"
	FactService FactKind = "service"
	FactCred    FactKind = "credential"
	FactVuln    FactKind = "vulnerability"
	FactLoot    FactKind = "loot"
	FactFlag    FactKind = "flag"
	FactNote    FactKind = "note"
)

// AllFactKinds returns all valid fact kinds.
func AllFactKinds() []FactKind {
	return []FactKind{FactHost, FactService, FactCred, FactVuln, FactLoot, FactFlag, FactNote}
}

// Fact represents a piece of intelligence gathered during operations.
type Fact struct {
	ID        string   `json:"id"`
	Kind      FactKind `json:"kind"`
	TaskID    string   `json:"task_id,omitempty"`
	SessionID string   `json:"session_id,omitempty"`

	// Core data
	Title    string            `json:"title"`
	Content  string            `json:"content"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Tags     []string          `json:"tags,omitempty"`

	// Relationships
	SourceIDs  []string `json:"source_ids,omitempty"`  // Facts that led to this one
	DerivedIDs []string `json:"derived_ids,omitempty"` // Facts derived from this one

	// Confidence & Status
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
	Verified   bool    `json:"verified"`
	Active     bool    `json:"active"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Provenance
	Agent  string `json:"agent,omitempty"`  // Agent that found this
	Method string `json:"method,omitempty"` // How it was found
}

// NewFact creates a new fact with defaults.
func NewFact(kind FactKind, title, content string) *Fact {
	return &Fact{
		ID:         generateFactID(),
		Kind:       kind,
		Title:      title,
		Content:    content,
		Metadata:   make(map[string]string),
		Tags:       []string{},
		SourceIDs:  []string{},
		DerivedIDs: []string{},
		Confidence: 0.5,
		Verified:   false,
		Active:     true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

// HostFact creates a host fact with standard metadata.
func HostFact(ip, hostname string, ports []string) *Fact {
	f := NewFact(FactHost, ip, fmt.Sprintf("Host: %s (%s)", ip, hostname))
	f.Metadata["ip"] = ip
	f.Metadata["hostname"] = hostname
	if len(ports) > 0 {
		f.Metadata["ports"] = joinStrings(ports, ",")
	}
	return f
}

// ServiceFact creates a service fact.
func ServiceFact(host, port, protocol, name string) *Fact {
	f := NewFact(FactService, fmt.Sprintf("%s:%s/%s", host, port, protocol),
		fmt.Sprintf("Service: %s on %s:%s", name, host, port))
	f.Metadata["host"] = host
	f.Metadata["port"] = port
	f.Metadata["protocol"] = protocol
	f.Metadata["service"] = name
	return f
}

// CredFact creates a credential fact.
func CredFact(username, password, service string) *Fact {
	f := NewFact(FactCred,
		fmt.Sprintf("%s@%s", username, service),
		fmt.Sprintf("Credential: %s:%s on %s", username, maskString(password), service))
	f.Metadata["username"] = username
	f.Metadata["password"] = password
	f.Metadata["service"] = service
	f.Confidence = 0.8
	f.Tags = append(f.Tags, "sensitive")
	return f
}

// VulnFact creates a vulnerability fact.
func VulnFact(name, severity, description, cveID string) *Fact {
	f := NewFact(FactVuln, name, description)
	f.Metadata["severity"] = severity
	f.Metadata["cve_id"] = cveID
	f.Tags = append(f.Tags, "vuln", severity)
	switch severity {
	case "critical":
		f.Confidence = 0.95
	case "high":
		f.Confidence = 0.9
	case "medium":
		f.Confidence = 0.7
	default:
		f.Confidence = 0.5
	}
	return f
}

// LootFact creates a loot fact (files, data exfiltrated).
func LootFact(lootType, path, description string) *Fact {
	f := NewFact(FactLoot, lootType, description)
	f.Metadata["type"] = lootType
	f.Metadata["path"] = path
	f.Tags = append(f.Tags, "loot", lootType)
	return f
}

// FlagFact creates a CTF-style flag fact.
func FlagFact(flag, challenge, category string) *Fact {
	f := NewFact(FactFlag, flag, fmt.Sprintf("Flag: %s from %s [%s]", flag, challenge, category))
	f.Metadata["challenge"] = challenge
	f.Metadata["category"] = category
	f.Confidence = 1.0
	f.Verified = true
	f.Tags = append(f.Tags, "flag", category)
	return f
}

// ToJSON serializes the fact to JSON.
func (f *Fact) ToJSON() ([]byte, error) {
	return json.Marshal(f)
}

// FactFromJSON deserializes a fact from JSON.
func FactFromJSON(data []byte) (*Fact, error) {
	var f Fact
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
