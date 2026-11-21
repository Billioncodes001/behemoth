package security

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ============================================================
// INDICATORS OF COMPROMISE (IOC) BLOCKLIST
// These IPs are known malicious C2/callback servers
// ============================================================

// IOCs contains known malicious IPs that should be blocked
var IOCs = []string{
	"38.244.50.120", "144.172.64.60", "144.172.64.99",
	"144.172.64.128", "187.15.88.186", "187.15.90.217",
	"187.15.89.186", "101.53.80.20", "205.214.59.31",
	"124.155.252.63", "154.201.79.246", "23.248.249.90",
	"23.158.220.98", "103.248.148.84", "203.160.133.172",
	"209.209.85.38", "199.19.95.66", "199.19.95.67",
	"199.19.95.68", "91.92.240.238", "85.11.168.45",
	"178.16.54.129", "31.77.229.35", "85.11.167.52",
}

// SuspiciousUA contains known bot/scanner user agents
var SuspiciousUA = []string{
	"sqlmap", "nikto", "nmap", "masscan", "zgrab",
	"dirbuster", "gobuster", "wfuzz", "ffuf", "nuclei",
	"python-requests", "curl/", "wget/", "go-http-client",
	"bot", "spider", "crawler", "scanner", "harvest",
	"metasploit", "burpsuite", "owasp", "acunetix",
	"nessus", "openvas", "w3af", "skipfish", "wpscan",
}

// WebShellExtensions contains dangerous file extensions
var WebShellExtensions = map[string]bool{
	".php": true, ".phtml": true, ".php3": true, ".php4": true,
	".php5": true, ".php7": true, ".phps": true,
	".asp": true, ".aspx": true, ".ashx": true,
	".jsp": true, ".jspx": true, ".jspa": true,
	".cgi": true, ".pl": true, ".py": true,
}

// NewIOCBlocklist creates a new IOC blocklist
func NewIOCBlocklist() *IOCBlocklist {
	bl := &IOCBlocklist{
		blockedIPs:  make(map[string]bool),
		blockedNets: make([]*net.IPNet, 0),
		stats:       &BlocklistStats{BlockedIPs: make([]string, 0, len(IOCs))},
	}
	for _, ip := range IOCs {
		bl.blockedIPs[ip] = true
		bl.stats.BlockedIPs = append(bl.stats.BlockedIPs, ip)
	}
	return bl
}

// SetBlockedIPs replaces the current blocked IP list (used when loading persisted IOCs from DB).
func (bl *IOCBlocklist) SetBlockedIPs(ips []string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.blockedIPs = make(map[string]bool, len(ips))
	bl.stats.BlockedIPs = make([]string, 0, len(ips))
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		bl.blockedIPs[ip] = true
		bl.stats.BlockedIPs = append(bl.stats.BlockedIPs, ip)
	}
}

// IsBlockedIP checks only whether the client IP is on the IOC blocklist (without heuristic URL/UA scoring).
func (bl *IOCBlocklist) IsBlockedIP(r *http.Request) (bool, string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.stats.TotalChecked++
	clientIP := bl.extractIP(r)
	if bl.isIOCIp(clientIP) {
		bl.stats.IocBlocks++
		bl.stats.TotalBlocked++
		bl.stats.LastBlockTime = time.Now()
		return true, clientIP
	}
	return false, clientIP
}

// SecurityResult represents the result of a security check
type SecurityResult struct {
	Allowed     bool      `json:"allowed"`
	ThreatScore int       `json:"threat_score"`
	Flags       []string  `json:"flags"`
	BlockReason string    `json:"block_reason,omitempty"`
	CheckTime   time.Time `json:"check_time"`
	ClientIP    string    `json:"client_ip,omitempty"`
}

// CheckRequest checks if a request should be blocked
func (bl *IOCBlocklist) CheckRequest(r *http.Request) *SecurityResult {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	bl.stats.TotalChecked++
	result := &SecurityResult{
		Allowed:     true,
		ThreatScore: 0,
		Flags:       []string{},
		CheckTime:   time.Now(),
	}

	clientIP := bl.extractIP(r)
	result.ClientIP = clientIP

	// 1. Check IOC blocklist
	if bl.isIOCIp(clientIP) {
		result.Allowed = false
		result.ThreatScore += 100
		result.Flags = append(result.Flags, "IOC_IP_BLOCKED")
		bl.stats.IocBlocks++
		bl.stats.TotalBlocked++
		bl.stats.LastBlockTime = time.Now()
		return result
	}

	// 2. Check User-Agent
	if bl.isSuspiciousUA(r.UserAgent()) {
		result.ThreatScore += 20
		result.Flags = append(result.Flags, "SUSPICIOUS_USER_AGENT")
	}

	// 3. Check URL patterns
	if score, reason := bl.checkURLPatterns(r.URL.Path); score > 0 {
		result.ThreatScore += score
		result.Flags = append(result.Flags, reason)
	}

	// 4. Block if threat score >= 70
	if result.ThreatScore >= 70 {
		result.Allowed = false
		bl.stats.PatternBlocks++
		bl.stats.TotalBlocked++
	}

	return result
}

// isIOCIp checks if IP is in the IOC list
func (bl *IOCBlocklist) isIOCIp(ip string) bool {
	if bl.blockedIPs[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range bl.blockedNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// isSuspiciousUA checks if user agent looks like a bot/scanner
func (bl *IOCBlocklist) isSuspiciousUA(ua string) bool {
	uaLower := strings.ToLower(ua)
	for _, s := range SuspiciousUA {
		if strings.Contains(uaLower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// checkURLPatterns checks URL against suspicious patterns
func (bl *IOCBlocklist) checkURLPatterns(url string) (int, string) {
	patterns := []struct {
		p, r string
		s    int
	}{
		{"/.env", "ENV_ACCESS", 20},
		{"/wp-admin", "WP_SCAN", 10},
		{"/phpmyadmin", "PMA_ACCESS", 25},
		{"/.git", "GIT_EXPOSURE", 30},
		{"union.*select", "SQL_INJECTION", 45},
		{"../", "PATH_TRAVERSAL", 35},
	}
	urlLower := strings.ToLower(url)
	for _, pat := range patterns {
		if strings.Contains(urlLower, pat.p) {
			return pat.s, pat.r
		}
	}
	return 0, ""
}

// extractIP extracts client IP from request
func (bl *IOCBlocklist) extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if parts := strings.Split(xff, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		return r.RemoteAddr
	}
	return ip
}

// GetStats returns blocklist statistics
func (bl *IOCBlocklist) GetStats() *BlocklistStats {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return bl.stats
}

// IOCBlocklist provides IOC blocking functionality
type IOCBlocklist struct {
	blockedIPs  map[string]bool
	blockedNets []*net.IPNet
	mu          sync.RWMutex
	stats       *BlocklistStats
}

// BlocklistStats tracks blocking statistics
type BlocklistStats struct {
	TotalChecked  int64     `json:"total_checked"`
	TotalBlocked  int64     `json:"total_blocked"`
	IocBlocks     int64     `json:"ioc_blocks"`
	PatternBlocks int64     `json:"pattern_blocks"`
	LastBlockTime time.Time `json:"last_block_time"`
	BlockedIPs    []string  `json:"blocked_ips"`
}

// AddBlockedIP adds an IP to the blocklist
func (bl *IOCBlocklist) AddBlockedIP(ip, reason string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.blockedIPs[ip] = true
	bl.stats.BlockedIPs = append(bl.stats.BlockedIPs, ip)
	bl.stats.TotalBlocked++
	log.Printf("[security] IP added to blocklist: %s (reason: %s)", ip, reason)
}

// RemoveBlockedIP removes an IP from the blocklist
func (bl *IOCBlocklist) RemoveBlockedIP(ip string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	delete(bl.blockedIPs, ip)
	// Remove from stats list
	for i, b := range bl.stats.BlockedIPs {
		if b == ip {
			bl.stats.BlockedIPs = append(bl.stats.BlockedIPs[:i], bl.stats.BlockedIPs[i+1:]...)
			break
		}
	}
	log.Printf("[security] IP removed from blocklist: %s", ip)
}
