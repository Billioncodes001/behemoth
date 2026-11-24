// Package agent implements IOC (Indicators of Compromise) collection and management.
// Inspired by NukeRat's IOC collection system, adapted for BEHEMOTH's pentest workflow.
package agent

import (
	"crypto/sha256"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------- Types ----------

// IOCType represents the type of an indicator.
type IOCType string

const (
	IOCIPv4   IOCType = "ipv4"
	IOCIPv6   IOCType = "ipv6"
	IOCDomain IOCType = "domain"
	IOCURL    IOCType = "url"
	IOCFile   IOCType = "file"
	IOCSHA256 IOCType = "hash_sha256"
	IOCEmail  IOCType = "email"
	IOCCIDR   IOCType = "cidr"
)

// IOC represents a single Indicator of Compromise.
type IOC struct {
	ID         int64     `json:"id"`
	Type       IOCType   `json:"type"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	TaskID     *int64    `json:"task_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	Confidence int       `json:"confidence"`
	Severity   string    `json:"severity"`
	Tags       []string  `json:"tags,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Count      int       `json:"count"`
	Context    string    `json:"context,omitempty"`
	Verified   bool      `json:"verified"`
}

// IOCFilter defines filters for IOC queries.
type IOCFilter struct {
	Type      IOCType `json:"type,omitempty"`
	TaskID    *int64  `json:"task_id,omitempty"`
	SessionID string  `json:"session_id,omitempty"`
	Verified  *bool   `json:"verified,omitempty"`
	Severity  string  `json:"severity,omitempty"`
	Limit     int     `json:"limit,omitempty"`
}

// IOCStats contains statistics about IOCs.
type IOCStats struct {
	Total       int             `json:"total"`
	ByType      map[IOCType]int `json:"by_type"`
	BySeverity  map[string]int  `json:"by_severity"`
	Verified    int             `json:"verified"`
	Unverified  int             `json:"unverified"`
	UniqueHosts int             `json:"unique_hosts"`
}

// ---------- Patterns ----------
var (
	ipv4Pattern     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})\b`)
	ipv6Pattern     = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
	domainPattern   = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,63}\b`)
	urlPattern      = regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `[\]]+`)
	emailPattern    = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	sha256Pattern   = regexp.MustCompile(`(?i)\b[a-f0-9]{64}\b`)
	cidrPattern     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})/(?:[12]?\d|3[0-2])\b`)
	filePathPattern = regexp.MustCompile(`(?:[A-Za-z]:\\[^\s;|&"<>]+|/(?:[^\s;|&"<>]+/)*[^\s;&"<>]+\.\w{1,10})`)

	sensitiveExtensions = map[string]bool{
		"exe": true, "dll": true, "so": true, "dylib": true,
		"ps1": true, "bat": true, "cmd": true, "sh": true,
		"php": true, "asp": true, "aspx": true, "jsp": true,
		"conf": true, "ini": true, "cfg": true, "env": true,
		"key": true, "pem": true, "crt": true, "pfx": true,
		"db": true, "sql": true, "bak": true, "zip": true,
	}
)

// ---------- Collector ----------

// Collector extracts and manages IOCs.
type Collector struct {
	mu     sync.RWMutex
	iocs   map[string]*IOC
	order  []*IOC
	config CollectorConfig
}

// CollectorConfig holds collector configuration.
type CollectorConfig struct {
	AutoExtract bool     `json:"auto_extract"`
	MaxIOCs     int      `json:"max_iocs"`
	Dedupe      bool     `json:"dedupe"`
	Tags        []string `json:"default_tags"`
}

// NewCollector creates a new IOC collector.
func NewCollector(config CollectorConfig) *Collector {
	if config.MaxIOCs == 0 {
		config.MaxIOCs = 10000
	}
	return &Collector{
		iocs:   make(map[string]*IOC),
		order:  make([]*IOC, 0),
		config: config,
	}
}

// ExtractFromText extracts IOCs from arbitrary text.
func (c *Collector) ExtractFromText(text, source string, taskID *int64, sessionID string) []*IOC {
	if !c.config.AutoExtract || text == "" {
		return nil
	}
	var extracted []*IOC
	extracted = append(extracted, c.extractIPv4(text, source, taskID, sessionID)...)
	extracted = append(extracted, c.extractDomains(text, source, taskID, sessionID)...)
	extracted = append(extracted, c.extractURLs(text, source, taskID, sessionID)...)
	extracted = append(extracted, c.extractEmails(text, source, taskID, sessionID)...)
	extracted = append(extracted, c.extractHashes(text, source, taskID, sessionID)...)
	extracted = append(extracted, c.extractFilePaths(text, source, taskID, sessionID)...)
	for _, ioc := range extracted {
		c.Add(ioc)
	}
	return extracted
}

// Add adds an IOC to the collector (with deduplication).
func (c *Collector) Add(ioc *IOC) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := fmt.Sprintf("%s:%s", ioc.Type, strings.ToLower(ioc.Value))
	if existing, ok := c.iocs[key]; ok {
		existing.LastSeen = time.Now()
		existing.Count++
		for _, tag := range ioc.Tags {
			existing.Tags = append(existing.Tags, tag)
		}
		return false
	}
	if c.config.MaxIOCs > 0 && len(c.iocs) >= c.config.MaxIOCs {
		return false
	}
	if ioc.FirstSeen.IsZero() {
		ioc.FirstSeen = time.Now()
	}
	if ioc.LastSeen.IsZero() {
		ioc.LastSeen = ioc.FirstSeen
	}
	if ioc.Count == 0 {
		ioc.Count = 1
	}
	if ioc.Confidence == 0 {
		ioc.Confidence = 50
	}
	if len(ioc.Tags) == 0 {
		ioc.Tags = append(ioc.Tags, c.config.Tags...)
	}
	if ioc.Severity == "" {
		ioc.Severity = c.classifySeverity(ioc)
	}
	c.iocs[key] = ioc
	c.order = append(c.order, ioc)
	return true
}

// Get retrieves IOCs matching the filter.
func (c *Collector) Get(filter IOCFilter) []*IOC {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var result []*IOC
	for _, ioc := range c.order {
		if filter.Type != "" && ioc.Type != filter.Type {
			continue
		}
		if filter.TaskID != nil && (ioc.TaskID == nil || *ioc.TaskID != *filter.TaskID) {
			continue
		}
		if filter.Severity != "" && ioc.Severity != filter.Severity {
			continue
		}
		result = append(result, ioc)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result
}

// GetAll returns all IOCs.
func (c *Collector) GetAll() []*IOC { return c.Get(IOCFilter{}) }

// Stats returns IOC statistics.
func (c *Collector) Stats() IOCStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stats := IOCStats{
		Total:      len(c.iocs),
		ByType:     make(map[IOCType]int),
		BySeverity: make(map[string]int),
	}
	hosts := make(map[string]bool)
	for _, ioc := range c.order {
		stats.ByType[ioc.Type]++
		_ = stats.BySeverity[ioc.Severity] // Track severity counts
		if ioc.Verified {
			stats.Verified++
		} else {
			stats.Unverified++
		}
		if ioc.Type == IOCDomain || ioc.Type == IOCIPv4 {
			hosts[ioc.Value] = true
		}
	}
	stats.UniqueHosts = len(hosts)
	return stats
}

// Clear removes all IOCs.
func (c *Collector) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.iocs = make(map[string]*IOC)
	c.order = make([]*IOC, 0)
}

// MarkVerified marks an IOC as verified by value.
func (c *Collector) MarkVerified(typeKey string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, ioc := range c.iocs {
		if strings.HasSuffix(key, strings.ToLower(typeKey)) {
			ioc.Verified = true
			return true
		}
	}
	return false
}

// classifySeverity assigns severity based on IOC type and context.
func (c *Collector) classifySeverity(ioc *IOC) string {
	switch ioc.Type {
	case IOCIPv4, IOCIPv6:
		if isPrivateIP(ioc.Value) {
			return "low"
		}
		return "medium"
	case IOCDomain:
		return "medium"
	case IOCURL:
		if strings.Contains(ioc.Value, "admin") || strings.Contains(ioc.Value, "login") {
			return "high"
		}
		return "medium"
	case IOCSHA256:
		return "high"
	default:
		return "info"
	}
}

// ---------- Extraction Methods ----------

func (c *Collector) extractIPv4(text, source string, taskID *int64, sessionID string) []*IOC {
	var results []*IOC
	for _, match := range ipv4Pattern.FindAllString(text, -1) {
		results = append(results, &IOC{Type: IOCIPv4, Value: match, Source: source, TaskID: taskID, SessionID: sessionID})
	}
	return results
}

func (c *Collector) extractDomains(text, source string, taskID *int64, sessionID string) []*IOC {
	var results []*IOC
	for _, match := range domainPattern.FindAllString(text, -1) {
		if isFalsePositiveDomain(match) {
			continue
		}
		results = append(results, &IOC{Type: IOCDomain, Value: strings.ToLower(match), Source: source, TaskID: taskID, SessionID: sessionID})
	}
	return results
}

func (c *Collector) extractURLs(text, source string, taskID *int64, sessionID string) []*IOC {
	var results []*IOC
	for _, match := range urlPattern.FindAllString(text, -1) {
		sev := "medium"
		lower := strings.ToLower(match)
		if strings.Contains(lower, "admin") || strings.Contains(lower, "login") {
			sev = "high"
		}
		results = append(results, &IOC{Type: IOCURL, Value: match, Source: source, TaskID: taskID, SessionID: sessionID, Severity: sev})
	}
	return results
}

func (c *Collector) extractEmails(text, source string, taskID *int64, sessionID string) []*IOC {
	var results []*IOC
	for _, match := range emailPattern.FindAllString(text, -1) {
		results = append(results, &IOC{Type: IOCEmail, Value: strings.ToLower(match), Source: source, TaskID: taskID, SessionID: sessionID})
	}
	return results
}

func (c *Collector) extractHashes(text, source string, taskID *int64, sessionID string) []*IOC {
	var results []*IOC
	for _, match := range sha256Pattern.FindAllString(text, -1) {
		results = append(results, &IOC{Type: IOCSHA256, Value: strings.ToUpper(match), Source: source, TaskID: taskID, SessionID: sessionID, Severity: "high"})
	}
	return results
}

func (c *Collector) extractFilePaths(text, source string, taskID *int64, sessionID string) []*IOC {
	var results []*IOC
	for _, match := range filePathPattern.FindAllString(text, -1) {
		ext := getExt(match)
		if ext != "" && !sensitiveExtensions[ext] {
			continue
		}
		results = append(results, &IOC{Type: IOCFile, Value: match, Source: source, TaskID: taskID, SessionID: sessionID, Severity: "medium"})
	}
	return results
}

// ---------- Utility Functions ----------

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	privateRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func isFalsePositiveDomain(domain string) bool {
	falsePositives := []string{"localhost", "example.com", "test.com", "the", "this", "that", "with", "from"}
	lower := strings.ToLower(domain)
	for _, fp := range falsePositives {
		if lower == fp {
			return true
		}
	}
	if len(strings.Split(lower, ".")) <= 2 && len(lower) <= 3 {
		return true
	}
	return false
}

func getExt(path string) string {
	lastDot := strings.LastIndex(path, ".")
	if lastDot == -1 {
		return ""
	}
	return path[lastDot+1:]
}

// ComputeFileHash computes SHA256 hash of content.
func ComputeFileHash(content []byte) string {
	hash := sha256.Sum256(content)
	return fmt.Sprintf("%x", hash)
}
