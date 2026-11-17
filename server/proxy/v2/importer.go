package proxyv2

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ImportProxies parses proxy data in multiple formats and adds to pool.
func (p *Pool) ImportProxies(data string, defaultType ProxyType) (*ImportResult, error) {
	// Detect format
	data = strings.TrimSpace(data)
	if strings.HasPrefix(data, "[") || strings.HasPrefix(data, "{") {
		return p.importJSON(data)
	}
	if strings.Contains(data, ",") && strings.Count(data, "\n") < strings.Count(data, ",") {
		return p.importCSV(data, defaultType)
	}
	return p.importLines(data, defaultType), nil
}

// importLines parses one-proxy-per-line format.
func (p *Pool) importLines(data string, defaultType ProxyType) *ImportResult {
	result := &ImportResult{}
	scanner := bufio.NewScanner(strings.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }

		px, err := parseProxyLine(line, defaultType)
		if err != nil {
			result.Errors = append(result.Errors, ImportError{
				Line: lineNum, Input: line, Error: err.Error(),
			})
			continue
		}

		// Check for duplicates
		isDup := false
		for _, existing := range p.GetProxies() {
			if existing.Host == px.Host && existing.Port == px.Port {
				isDup = true
				result.Skipped++
				break
			}
		}
		if isDup { continue }

		if err := p.AddProxy(*px); err != nil {
			result.Errors = append(result.Errors, ImportError{
				Line: lineNum, Input: line, Error: err.Error(),
			})
		} else {
			result.Imported++
		}
	}
	return result
}

// parseProxyLine parses a single proxy line into ProxyInfo.
// Supports: "host:port", "type://host:port", "type://user:pass@host:port",
// and optional pipe-separated metadata: "type://user:pass@host:port|Name|Remark"
func parseProxyLine(line string, defaultType ProxyType) (*ProxyInfo, error) {
	line = strings.TrimSpace(line)
	var name, notes string
	if strings.Contains(line, "|") {
		pipeParts := strings.SplitN(line, "|", 3)
		line = strings.TrimSpace(pipeParts[0])
		if len(pipeParts) >= 2 {
			name = strings.TrimSpace(pipeParts[1])
		}
		if len(pipeParts) >= 3 {
			notes = strings.TrimSpace(pipeParts[2])
		}
	}

	// Try URL format first (with scheme)
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %w", err)
		}
		host, port, err := splitHostPort(u.Host)
		if err != nil {
			return nil, fmt.Errorf("invalid host:port: %w", err)
		}
		pt := ProxyType(u.Scheme)
		if pt == "" {
			pt = defaultType
		}
		pass, _ := u.User.Password()
		return &ProxyInfo{
			Type: pt, Host: host, Port: port,
			Username: u.User.Username(), Password: pass,
			Name: name, Notes: notes,
		}, nil
	}

	// Simple host:port format
	parts := strings.Split(line, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("expected 'host:port' or 'type://host:port', got: %s", line)
	}
	host := strings.TrimSpace(parts[0])
	var port int
	if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &port); err != nil {
		return nil, fmt.Errorf("invalid port: %s", parts[1])
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range (1-65535): %d", port)
	}

	return &ProxyInfo{Type: defaultType, Host: host, Port: port, Name: name, Notes: notes}, nil
}

// importCSV parses CSV format: "host,port,type,user,pass"
func (p *Pool) importCSV(data string, defaultType ProxyType) (*ImportResult, error) {
	result := &ImportResult{}
	scanner := bufio.NewScanner(strings.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }

		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			result.Errors = append(result.Errors, ImportError{
				Line: lineNum, Input: line, Error: "need at least host,port",
			})
			continue
		}
		host := strings.TrimSpace(parts[0])
		var port int
		if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &port); err != nil {
			result.Errors = append(result.Errors, ImportError{
				Line: lineNum, Input: line, Error: "invalid port",
			})
			continue
		}
		pt := defaultType
		if len(parts) >= 3 { pt = ProxyType(strings.TrimSpace(parts[2])) }
		var user, pass string
		if len(parts) >= 4 { user = strings.TrimSpace(parts[3]) }
		if len(parts) >= 5 { pass = strings.TrimSpace(parts[4]) }

		px := &ProxyInfo{Type: pt, Host: host, Port: port, Username: user, Password: pass}
		if err := p.AddProxy(*px); err != nil {
			result.Errors = append(result.Errors, ImportError{Line: lineNum, Input: line, Error: err.Error()})
		} else {
			result.Imported++
		}
	}
	return result, nil
}

// importJSON parses JSON array of ProxyInfo objects.
func (p *Pool) importJSON(data string) (*ImportResult, error) {
	result := &ImportResult{}
	var proxies []ProxyInfo
	if err := json.Unmarshal([]byte(data), &proxies); err != nil {
		// Try single object
		var single ProxyInfo
		if err2 := json.Unmarshal([]byte(data), &single); err2 != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		proxies = []ProxyInfo{single}
	}
	for _, px := range proxies {
		if err := p.AddProxy(px); err != nil {
			result.Errors = append(result.Errors, ImportError{Input: px.Host, Error: err.Error()})
		} else {
			result.Imported++
		}
	}
	return result, nil
}

// splitHostPort splits "host:port" into components.
func splitHostPort(hostport string) (string, int, error) {
	colonIdx := strings.LastIndex(hostport, ":")
	if colonIdx == -1 { return "", 0, fmt.Errorf("missing port in %s", hostport) }
	host := hostport[:colonIdx]
	var port int
	if _, err := fmt.Sscanf(hostport[colonIdx+1:], "%d", &port); err != nil {
		return "", 0, err
	}
	return host, port, nil
}