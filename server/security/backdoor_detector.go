package security

import (
	"io"
	"net/http"
	"strings"
)

// ============================================================
// BACKDOOR DETECTOR
// Detects common backdoor patterns including:
// - The "captcha" RCE (tomicdd/artex style)
// - Web shells
// - Magic prefix commands
// ============================================================

// BackdoorDetector detects malicious backdoor patterns
type BackdoorDetector struct {
	magicPrefixes []string
	suspiciousFields []string
}

// NewBackdoorDetector creates a new backdoor detector
func NewBackdoorDetector() *BackdoorDetector {
	return &BackdoorDetector{
		magicPrefixes: []string{"!", "$(", "`", "eval(", "exec("},
		suspiciousFields: []string{
			"captcha", "token", "verify", "challenge",
			"debug", "test", "admin_key", "backdoor",
			"auth_bypass", "secret_key",
		},
	}
}

// CheckRequest checks for backdoor patterns in request
func (bd *BackdoorDetector) CheckRequest(r *http.Request) *BackdoorCheckResult {
	result := &BackdoorCheckResult{
		Suspicious: false,
		Patterns:  []string{},
	}

	// Check URL for suspicious patterns
	if bd.hasSuspiciousURLPattern(r.URL.Path) {
		result.Suspicious = true
		result.Patterns = append(result.Patterns, "SUSPICIOUS_URL")
	}

	// For POST requests, we'd check body (requires middleware)
	if r.Method == "POST" {
		// Log for monitoring - actual body inspection in middleware
		if bd.hasSuspiciousURLPath(r.URL.Path) {
			result.Suspicious = true
			result.Patterns = append(result.Patterns, "SUSPICIOUS_ENDPOINT")
		}
	}

	return result
}

// CheckBody checks request body for backdoor patterns
// Call this from middleware after reading body
func (bd *BackdoorDetector) CheckBody(body []byte, urlPath string) *BackdoorCheckResult {
	result := &BackdoorCheckResult{
		Suspicious: false,
		Patterns:  []string{},
	}

	bodyStr := string(body)

	// Check for magic prefix RCE pattern (!cmd style)
	for _, prefix := range bd.magicPrefixes {
		if strings.HasPrefix(bodyStr, prefix) {
			result.Suspicious = true
			result.Patterns = append(result.Patterns,
				"MAGIC_PREFIX_RCE: "+prefix)
		}
	}

	// Check for captcha field with executable content
	if strings.Contains(urlPath, "captcha") ||
	   strings.Contains(urlPath, "login") ||
	   strings.Contains(urlPath, "auth") {
		// Look for suspicious patterns in form data
		suspiciousPatterns := []string{
			";", "|", "&", "$(", "`", "eval(",
			"system(", "exec(", "passthru(",
		}
		for _, pat := range suspiciousPatterns {
			if strings.Contains(bodyStr, pat) {
				result.Suspicious = true
				result.Patterns = append(result.Patterns,
					"SUSPICIOUS_FORM_CONTENT")
				break
			}
		}
	}

	return result
}

// hasSuspiciousURLPattern checks URL for attack patterns
func (bd *BackdoorDetector) hasSuspiciousURLPattern(url string) bool {
	suspiciousPaths := []string{
		"/.env", "/.git/", "/.svn/",
		"/phpmyadmin", "/admin/config",
		"/shell", "/cmd", "/exec",
		"/debug", "/actuator",
		"/backup", "/dump",
		"/.htaccess", "/.htpasswd",
		"/web.config", "/web.xml",
	}
	urlLower := strings.ToLower(url)
	for _, p := range suspiciousPaths {
		if strings.Contains(urlLower, p) {
			return true
		}
	}
	return false
}

// hasSuspiciousURLPath checks if path is commonly targeted
func (bd *BackdoorDetector) hasSuspiciousURLPath(path string) bool {
	targeted := []string{
		"/api/login", "/api/auth", "/api/verify",
		"/api/captcha", "/api/token",
		"/admin", "/wp-login", "/user/login",
	}
	pathLower := strings.ToLower(path)
	for _, t := range targeted {
		if strings.Contains(pathLower, t) {
			return true
		}
	}
	return false
}

// BackdoorCheckResult represents backdoor check result
type BackdoorCheckResult struct {
	Suspicious bool     `json:"suspicious"`
	Patterns   []string `json:"patterns"`
	Severity   string   `json:"severity,omitempty"`
}

// ReadBody safely reads request body for inspection
func ReadBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	return body, nil
}