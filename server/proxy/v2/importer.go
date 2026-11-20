package proxyv2

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func normalizeProxyType(pt ProxyType, fallback ProxyType) ProxyType {
	if fallback == "" {
		fallback = ProxyTypeHTTP
	}
	s := strings.ToLower(strings.TrimSpace(string(pt)))
	switch s {
	case "http":
		return ProxyTypeHTTP
	case "https":
		return ProxyTypeHTTPS
	case "socks5":
		return ProxyTypeSOCKS5
	case "socks5h":
		return ProxyTypeSOCKS5H
	case "socks4", "socks4a":
		return ProxyTypeSOCKS4
	case "":
		return fallback
	default:
		return ProxyType(s)
	}
}

func looksLikeHostOrIP(s string) bool {
	s = strings.TrimSpace(strings.Trim(s, "[]"))
	if s == "" || strings.ContainsAny(s, " \t@/") {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	return strings.Contains(s, ".") || strings.EqualFold(s, "localhost")
}

func parsePortInt(s string) (int, bool) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, false
	}
	return p, true
}

func maskInputSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	if px, err := ParseSingleProxyLine(s, ProxyTypeHTTP); err == nil && px != nil {
		return px.maskURL()
	}
	return s
}

// NormalizeProxyLineToURL parses any supported single-line proxy representation
// (host:port:user:pass, user:pass@host:port, host:port@user:pass, user:pass:host:port,
// scheme://user:pass@host:port, scheme://host:port:user:pass, host:port, and |Name|Remark)
// into a standard RFC3986 proxy URL plus optional name and remark.
func NormalizeProxyLineToURL(line string, defaultScheme string) (string, string, string, error) {
	defType := normalizeProxyType(ProxyType(defaultScheme), ProxyTypeHTTP)
	px, err := ParseSingleProxyLine(line, defType)
	if err != nil {
		return "", "", "", err
	}
	return px.BuildProxyURL(), px.Name, px.Notes, nil
}

// ParseSingleProxyLine parses a single proxy line in any common provider format.
func ParseSingleProxyLine(line string, defaultType ProxyType) (*ProxyInfo, error) {
	defaultType = normalizeProxyType(defaultType, ProxyTypeHTTP)
	line = strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
	if line == "" {
		return nil, fmt.Errorf("empty proxy line")
	}

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

	// Strip inline trailing "# remark" when separated by whitespace
	if idx := strings.Index(line, " #"); idx > 0 {
		if notes == "" {
			notes = strings.TrimSpace(line[idx+2:])
		}
		line = strings.TrimSpace(line[:idx])
	}

	scheme := defaultType
	rest := line
	hasExplicitScheme := false
	if idx := strings.Index(rest, "://"); idx > 0 {
		scheme = normalizeProxyType(ProxyType(rest[:idx]), defaultType)
		rest = strings.TrimSpace(rest[idx+3:])
		hasExplicitScheme = true
	}
	// Strip trailing path slash (e.g. "http://1.2.3.4:8080/")
	rest = strings.TrimRight(rest, "/")

	// Case 1: "@" separator -> either "user:pass@host:port" or "host:port@user:pass"
	if atIdx := strings.LastIndex(rest, "@"); atIdx > 0 && atIdx < len(rest)-1 {
		left := rest[:atIdx]
		right := rest[atIdx+1:]
		if host, port, err := splitHostPort(right); err == nil && looksLikeHostOrIP(host) {
			user, pass := splitUserPass(left, hasExplicitScheme)
			return &ProxyInfo{
				Type: scheme, Host: host, Port: port,
				Username: user, Password: pass,
				Name: name, Notes: notes,
			}, nil
		}
		if host, port, err := splitHostPort(left); err == nil && looksLikeHostOrIP(host) {
			user, pass := splitUserPass(right, false)
			return &ProxyInfo{
				Type: scheme, Host: host, Port: port,
				Username: user, Password: pass,
				Name: name, Notes: notes,
			}, nil
		}
	}

	// Case 2: Bracketed IPv6 "[::1]:port" or "[::1]:port:user:pass"
	if strings.HasPrefix(rest, "[") {
		closeIdx := strings.Index(rest, "]:")
		if closeIdx > 1 {
			host := rest[1:closeIdx]
			afterHost := rest[closeIdx+2:]
			segs := strings.SplitN(afterHost, ":", 3)
			port, ok := parsePortInt(segs[0])
			if !ok {
				return nil, fmt.Errorf("invalid port in %s", line)
			}
			var user, pass string
			if len(segs) >= 2 {
				user = segs[1]
			}
			if len(segs) == 3 {
				pass = segs[2]
			}
			return &ProxyInfo{
				Type: scheme, Host: host, Port: port,
				Username: user, Password: pass,
				Name: name, Notes: notes,
			}, nil
		}
	}

	// Case 3: Whitespace/tab/semicolon separated columns on a single line ("ip port user pass" or "ip;port;user;pass")
	if strings.ContainsAny(rest, ";\t ") && !strings.Contains(rest, ":") {
		fields := strings.FieldsFunc(rest, func(r rune) bool { return r == ';' || r == '\t' || r == ' ' })
		if len(fields) >= 2 {
			if port, ok := parsePortInt(fields[1]); ok && looksLikeHostOrIP(fields[0]) {
				var user, pass string
				if len(fields) >= 3 {
					user = fields[2]
				}
				if len(fields) >= 4 {
					pass = fields[3]
				}
				return &ProxyInfo{
					Type: scheme, Host: fields[0], Port: port,
					Username: user, Password: pass,
					Name: name, Notes: notes,
				}, nil
			}
		}
	}

	// Case 4: Colon-delimited formats:
	//   - "host:port"
	//   - "host:port:username:password" (Webshare / Oxylabs / IPRoyal / Smartproxy)
	//   - "username:password:host:port"
	parts := strings.Split(rest, ":")
	switch {
	case len(parts) == 2:
		port, ok := parsePortInt(parts[1])
		if !ok || !looksLikeHostOrIP(parts[0]) {
			return nil, fmt.Errorf("expected 'host:port', got: %s", maskInputSecret(line))
		}
		return &ProxyInfo{
			Type: scheme, Host: strings.TrimSpace(parts[0]), Port: port,
			Name: name, Notes: notes,
		}, nil

	case len(parts) >= 4:
		// Check "host:port:user:pass" first (parts[3:] rejoined in case password contains ':')
		if port, ok := parsePortInt(parts[1]); ok && looksLikeHostOrIP(parts[0]) {
			user := strings.TrimSpace(parts[2])
			pass := strings.Join(parts[3:], ":")
			return &ProxyInfo{
				Type: scheme, Host: strings.TrimSpace(parts[0]), Port: port,
				Username: user, Password: pass,
				Name: name, Notes: notes,
			}, nil
		}
		// Check "user:pass:host:port" (last two segments are host:port)
		last := len(parts) - 1
		if port, ok := parsePortInt(parts[last]); ok && looksLikeHostOrIP(parts[last-1]) {
			user := strings.TrimSpace(parts[0])
			pass := strings.Join(parts[1:last-1], ":")
			return &ProxyInfo{
				Type: scheme, Host: strings.TrimSpace(parts[last-1]), Port: port,
				Username: user, Password: pass,
				Name: name, Notes: notes,
			}, nil
		}
	}

	return nil, fmt.Errorf("unsupported proxy format (supported: host:port:user:pass, user:pass@host:port, scheme://user:pass@host:port, host:port)")
}

func splitUserPass(cred string, urlEncoded bool) (string, string) {
	u, p, hasPass := strings.Cut(cred, ":")
	if urlEncoded {
		if du, err := url.PathUnescape(u); err == nil {
			u = du
		}
		if hasPass {
			if dp, err := url.PathUnescape(p); err == nil {
				p = dp
			}
		}
	}
	return u, p
}

// ImportProxies parses proxy data in multiple formats (.txt, Webshare host:port:user:pass,
// URLs, CSV/TSV, JSON) and batch-inserts non-duplicate proxies with a single persistence sync.
func (p *Pool) ImportProxies(data string, defaultType ProxyType) (*ImportResult, error) {
	defaultType = normalizeProxyType(defaultType, ProxyTypeHTTP)
	data = strings.TrimSpace(strings.TrimPrefix(data, "\uFEFF"))
	if data == "" {
		return &ImportResult{}, nil
	}
	if strings.HasPrefix(data, "[") || strings.HasPrefix(data, "{") {
		return p.importJSON(data, defaultType)
	}
	if looksLikeCSVData(data) {
		return p.importCSV(data, defaultType)
	}
	return p.importLines(data, defaultType), nil
}

func looksLikeCSVData(data string) bool {
	firstLine, _, _ := strings.Cut(data, "\n")
	firstLine = strings.TrimSpace(firstLine)
	if strings.Contains(firstLine, "://") && !strings.Contains(firstLine, ",") {
		return false
	}
	return strings.Count(firstLine, ",") >= 1
}

func proxyDedupKey(px *ProxyInfo) string {
	return fmt.Sprintf("%s://%s@%s:%d", strings.ToLower(string(px.Type)), px.Username, strings.ToLower(px.Host), px.Port)
}

func (p *Pool) addBatchProxies(parsed []*ProxyInfo, result *ImportResult) error {
	if len(parsed) == 0 {
		return nil
	}
	p.state.mu.Lock()
	existingKeys := make(map[string]bool, len(p.state.proxies)+len(parsed))
	for i := range p.state.proxies {
		existingKeys[proxyDedupKey(&p.state.proxies[i])] = true
	}
	for _, px := range parsed {
		if px == nil || px.Host == "" || px.Port <= 0 {
			continue
		}
		px.Type = normalizeProxyType(px.Type, ProxyTypeHTTP)
		key := proxyDedupKey(px)
		if existingKeys[key] {
			result.Skipped++
			continue
		}
		existingKeys[key] = true
		p.appendProxyNoPersistLocked(*px)
		result.Imported++
	}
	err := p.persistLocked()
	result.ActiveProxyID = p.state.activeID
	p.state.mu.Unlock()
	return err
}

// importLines parses one-proxy-per-line format.
func (p *Pool) importLines(data string, defaultType ProxyType) *ImportResult {
	result := &ImportResult{}
	var batch []*ProxyInfo
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		px, err := ParseSingleProxyLine(line, defaultType)
		if err != nil {
			result.Errors = append(result.Errors, ImportError{
				Line: lineNum, Input: maskInputSecret(line), Error: err.Error(),
			})
			continue
		}
		batch = append(batch, px)
	}
	_ = p.addBatchProxies(batch, result)
	return result
}

// importCSV parses CSV/TSV files with or without headers:
// e.g. "ip,port,username,password", "host,port,type,user,pass", "protocol,host,port,user,pass", or single-column URLs.
func (p *Pool) importCSV(data string, defaultType ProxyType) (*ImportResult, error) {
	result := &ImportResult{}
	r := csv.NewReader(strings.NewReader(data))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	colMap := map[string]int{}
	hasHeader := false
	var batch []*ProxyInfo
	lineNum := 0

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		lineNum++
		if err != nil {
			result.Errors = append(result.Errors, ImportError{Line: lineNum, Error: err.Error()})
			continue
		}
		if len(rec) == 0 || (len(rec) == 1 && (strings.TrimSpace(rec[0]) == "" || strings.HasPrefix(strings.TrimSpace(rec[0]), "#"))) {
			continue
		}
		if lineNum == 1 && isCSVHeaderRow(rec) {
			hasHeader = true
			for idx, h := range rec {
				colMap[strings.ToLower(strings.TrimSpace(h))] = idx
			}
			continue
		}

		if len(rec) == 1 {
			px, perr := ParseSingleProxyLine(rec[0], defaultType)
			if perr != nil {
				result.Errors = append(result.Errors, ImportError{Line: lineNum, Input: maskInputSecret(rec[0]), Error: perr.Error()})
				continue
			}
			batch = append(batch, px)
			continue
		}

		var px *ProxyInfo
		var perr error
		if hasHeader {
			px, perr = parseCSVRecordWithHeader(rec, colMap, defaultType)
		} else {
			px, perr = parseCSVRecordPositional(rec, defaultType)
		}
		if perr != nil {
			result.Errors = append(result.Errors, ImportError{Line: lineNum, Input: maskInputSecret(strings.Join(rec, ",")), Error: perr.Error()})
			continue
		}
		batch = append(batch, px)
	}
	_ = p.addBatchProxies(batch, result)
	return result, nil
}

func isCSVHeaderRow(rec []string) bool {
	for _, cell := range rec {
		switch strings.ToLower(strings.TrimSpace(cell)) {
		case "ip", "host", "hostname", "address", "proxy_address", "server", "port", "username", "user", "password", "pass", "protocol", "type", "scheme", "proxy", "url":
			return true
		}
	}
	return false
}

func getCSVCol(rec []string, colMap map[string]int, aliases ...string) string {
	for _, a := range aliases {
		if idx, ok := colMap[a]; ok && idx >= 0 && idx < len(rec) {
			return strings.TrimSpace(rec[idx])
		}
	}
	return ""
}

func parseCSVRecordWithHeader(rec []string, colMap map[string]int, defaultType ProxyType) (*ProxyInfo, error) {
	if rawURL := getCSVCol(rec, colMap, "url", "proxy"); rawURL != "" {
		return ParseSingleProxyLine(rawURL, defaultType)
	}
	host := getCSVCol(rec, colMap, "ip", "host", "hostname", "address", "proxy_address", "server")
	portStr := getCSVCol(rec, colMap, "port")
	port, ok := parsePortInt(portStr)
	if !ok || !looksLikeHostOrIP(host) {
		return nil, fmt.Errorf("invalid CSV host/port")
	}
	pt := normalizeProxyType(ProxyType(getCSVCol(rec, colMap, "protocol", "type", "scheme")), defaultType)
	user := getCSVCol(rec, colMap, "username", "user", "login")
	pass := getCSVCol(rec, colMap, "password", "pass", "pwd")
	name := getCSVCol(rec, colMap, "name", "label")
	country := getCSVCol(rec, colMap, "country", "country_code")
	city := getCSVCol(rec, colMap, "city")
	return &ProxyInfo{
		Type: pt, Host: host, Port: port,
		Username: user, Password: pass,
		Name: name, Country: country, City: city,
	}, nil
}

func parseCSVRecordPositional(rec []string, defaultType ProxyType) (*ProxyInfo, error) {
	// Supports:
	//   host,port
	//   host,port,user,pass  (Webshare / standard 4-column CSV!)
	//   host,port,type,user,pass
	//   type,host,port,user,pass
	c0 := strings.TrimSpace(rec[0])
	c1 := strings.TrimSpace(rec[1])
	if isSchemeName(c0) && len(rec) >= 3 {
		port, ok := parsePortInt(rec[2])
		if !ok || !looksLikeHostOrIP(c1) {
			return nil, fmt.Errorf("invalid CSV protocol,host,port")
		}
		var user, pass string
		if len(rec) >= 4 {
			user = strings.TrimSpace(rec[3])
		}
		if len(rec) >= 5 {
			pass = strings.TrimSpace(rec[4])
		}
		return &ProxyInfo{Type: normalizeProxyType(ProxyType(c0), defaultType), Host: c1, Port: port, Username: user, Password: pass}, nil
	}

	port, ok := parsePortInt(c1)
	if !ok || !looksLikeHostOrIP(c0) {
		return nil, fmt.Errorf("invalid CSV host,port")
	}
	pt := defaultType
	var user, pass string
	if len(rec) == 4 {
		// 4 columns: ip,port,username,password (unless column 3 is a scheme like http/socks5)
		if isSchemeName(rec[2]) {
			pt = normalizeProxyType(ProxyType(rec[2]), defaultType)
			user = strings.TrimSpace(rec[3])
		} else {
			user = strings.TrimSpace(rec[2])
			pass = strings.TrimSpace(rec[3])
		}
	} else if len(rec) >= 5 {
		if isSchemeName(rec[2]) {
			pt = normalizeProxyType(ProxyType(rec[2]), defaultType)
			user = strings.TrimSpace(rec[3])
			pass = strings.TrimSpace(rec[4])
		} else {
			user = strings.TrimSpace(rec[2])
			pass = strings.TrimSpace(rec[3])
		}
	} else if len(rec) == 3 && isSchemeName(rec[2]) {
		pt = normalizeProxyType(ProxyType(rec[2]), defaultType)
	}
	return &ProxyInfo{Type: pt, Host: c0, Port: port, Username: user, Password: pass}, nil
}

func isSchemeName(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "http", "https", "socks5", "socks5h", "socks4", "socks4a":
		return true
	}
	return false
}

// importJSON parses JSON array of strings, JSON array of flexible proxy objects,
// single object, or {"proxies":[...]} / {"results":[...]} (including Webshare API JSON).
func (p *Pool) importJSON(data string, defaultType ProxyType) (*ImportResult, error) {
	result := &ImportResult{}
	var rawItems []json.RawMessage

	if strings.HasPrefix(data, "[") {
		if err := json.Unmarshal([]byte(data), &rawItems); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
	} else {
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal([]byte(data), &wrapper); err != nil {
			return nil, fmt.Errorf("invalid JSON object: %w", err)
		}
		for _, key := range []string{"proxies", "results", "data", "items", "list"} {
			if arrRaw, ok := wrapper[key]; ok && strings.HasPrefix(strings.TrimSpace(string(arrRaw)), "[") {
				_ = json.Unmarshal(arrRaw, &rawItems)
				break
			}
		}
		if len(rawItems) == 0 {
			rawItems = []json.RawMessage{json.RawMessage(data)}
		}
	}

	var batch []*ProxyInfo
	for idx, item := range rawItems {
		var strLine string
		if json.Unmarshal(item, &strLine) == nil {
			px, err := ParseSingleProxyLine(strLine, defaultType)
			if err != nil {
				result.Errors = append(result.Errors, ImportError{Line: idx + 1, Input: maskInputSecret(strLine), Error: err.Error()})
				continue
			}
			batch = append(batch, px)
			continue
		}

		var obj map[string]any
		if err := json.Unmarshal(item, &obj); err != nil {
			result.Errors = append(result.Errors, ImportError{Line: idx + 1, Error: err.Error()})
			continue
		}
		if urlStr := pickObjStr(obj, "url", "proxy"); urlStr != "" {
			px, err := ParseSingleProxyLine(urlStr, defaultType)
			if err != nil {
				result.Errors = append(result.Errors, ImportError{Line: idx + 1, Input: maskInputSecret(urlStr), Error: err.Error()})
				continue
			}
			batch = append(batch, px)
			continue
		}
		host := pickObjStr(obj, "host", "ip", "proxy_address", "server", "address", "hostname")
		port, ok := pickObjPort(obj, "port", "http_port", "socks_port")
		if !ok || !looksLikeHostOrIP(host) {
			result.Errors = append(result.Errors, ImportError{Line: idx + 1, Error: "missing host/ip or valid port in JSON object"})
			continue
		}
		pt := normalizeProxyType(ProxyType(pickObjStr(obj, "type", "protocol", "proxy_type", "scheme")), defaultType)
		batch = append(batch, &ProxyInfo{
			Type:     pt,
			Host:     host,
			Port:     port,
			Username: pickObjStr(obj, "username", "user", "login"),
			Password: pickObjStr(obj, "password", "pass", "pwd"),
			Name:     pickObjStr(obj, "name", "label"),
			Notes:    pickObjStr(obj, "notes", "remark"),
			Country:  pickObjStr(obj, "country", "country_code"),
			City:     pickObjStr(obj, "city"),
		})
	}
	_ = p.addBatchProxies(batch, result)
	return result, nil
}

func pickObjStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			if s, isStr := v.(string); isStr && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func pickObjPort(m map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			switch val := v.(type) {
			case float64:
				p := int(val)
				if p >= 1 && p <= 65535 {
					return p, true
				}
			case string:
				if p, ok := parsePortInt(val); ok {
					return p, true
				}
			}
		}
	}
	return 0, false
}

// splitHostPort splits "host:port" or "[ipv6]:port" into components.
func splitHostPort(hostport string) (string, int, error) {
	h, pStr, err := net.SplitHostPort(strings.TrimSpace(hostport))
	if err != nil {
		colonIdx := strings.LastIndex(hostport, ":")
		if colonIdx == -1 {
			return "", 0, fmt.Errorf("missing port in %s", hostport)
		}
		h = strings.Trim(hostport[:colonIdx], "[]")
		pStr = hostport[colonIdx+1:]
	}
	port, ok := parsePortInt(pStr)
	if !ok {
		return "", 0, fmt.Errorf("invalid port: %s", pStr)
	}
	return h, port, nil
}