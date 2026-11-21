package patchmonitor

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var knownTechKeywords = []string{
	"apache", "httpd", "tomcat", "struts", "nginx", "openresty", "iis", "caddy", "traefik", "haproxy", "envoy",
	"php", "laravel", "symfony", "codeigniter", "cakephp", "wordpress", "woocommerce", "drupal", "joomla", "magento",
	"python", "django", "flask", "fastapi", "gunicorn", "uvicorn", "werkzeug", "tornado",
	"nodejs", "node.js", "express", "nextjs", "next.js", "nuxt", "nestjs", "react", "vite", "webpack",
	"java", "spring", "springboot", "jetty", "wildfly", "jboss", "weblogic", "websphere", "log4j",
	"ruby", "rails", "puma", "unicorn", "golang", "gin", "dotnet", "asp.net", "blazor",
	"openssh", "ssh", "openssl", "mysql", "mariadb", "postgresql", "postgres", "redis", "mongodb", "elasticsearch", "memcached",
	"docker", "containerd", "kubernetes", "k8s", "jenkins", "gitlab", "gitea", "github enterprise", "teamcity", "nexus", "harbor",
	"grafana", "kibana", "prometheus", "zabbix", "nagios", "cacti", "phpmyadmin", "adminer",
	"keycloak", "okta", "fortinet", "fortios", "fortigate", "palo alto", "pan-os", "globalprotect", "cisco", "ivanti",
	"citrix", "netscaler", "f5", "big-ip", "sonicwall", "vmware", "vcenter", "esxi", "confluence", "jira", "bitbucket",
}

// AutoMatchMatchEntry describes one authorized asset enrolled or updated as an exploit target.
type AutoMatchEntry struct {
	TargetID    int64    `json:"target_id"`
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Service     string   `json:"service"`
	MatchedTech []string `json:"matched_tech"`
	MatchedCVEs []string `json:"matched_cves"`
	NewlyAdded  bool     `json:"newly_added"`
}

// ExtractVulnTechnologies extracts normalized product/technology tokens from a vulnerability record.
func ExtractVulnTechnologies(v Vulnerability) []string {
	blob := strings.ToLower(v.Title + " " + v.Description + " " + v.AffectedSoftware + " " + v.AffectedVersions)
	seen := map[string]bool{}
	var out []string
	for _, kw := range knownTechKeywords {
		if containsWordOrToken(blob, kw) && !seen[kw] {
			seen[kw] = true
			out = append(out, kw)
		}
	}
	return out
}

func containsWordOrToken(haystack, needle string) bool {
	idx := strings.Index(haystack, needle)
	for idx >= 0 {
		beforeOK := idx == 0 || !isAlphaNum(haystack[idx-1])
		end := idx + len(needle)
		afterOK := end == len(haystack) || !isAlphaNum(haystack[end])
		if beforeOK && afterOK {
			return true
		}
		next := strings.Index(haystack[idx+1:], needle)
		if next < 0 {
			break
		}
		idx = idx + 1 + next
	}
	return false
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func isWebVuln(v Vulnerability) bool {
	blob := strings.ToLower(v.Title + " " + v.Description)
	for _, w := range []string{"http", "web", "xss", "sql injection", "sqli", "csrf", "ssrf", "path traversal", "lfi", "authentication bypass", "cgi", "php", "nginx", "apache", "wordpress", "laravel", "spring", "nextjs"} {
		if strings.Contains(blob, w) {
			return true
		}
	}
	return false
}

// AutoMatchAuthorizedTargets correlates tracked vulnerabilities & generated exploits against
// ARTEX's authorized `assets` inventory (domains, subdomains, web services, IPs, tech fingerprints)
// and automatically enrolls matching in-scope targets into `exploit_targets`.
func (m *Monitor) AutoMatchAuthorizedTargets(vulns []Vulnerability) ([]AutoMatchEntry, error) {
	if m == nil || m.db == nil {
		return nil, nil
	}
	if len(vulns) == 0 {
		var err error
		vulns, err = m.GetVulnerabilities("all", 30)
		if err != nil {
			return nil, err
		}
	}

	// Build map: tech keyword -> list of CVE/Advisory labels
	techToCVEs := map[string][]string{}
	var webCVEs []string
	for _, v := range vulns {
		label := v.CVEID
		if label == "" {
			label = fmt.Sprintf("Vuln#%d", v.ID)
		}
		techs := ExtractVulnTechnologies(v)
		for _, t := range techs {
			if len(techToCVEs[t]) < 5 {
				techToCVEs[t] = appendUniqueStr(techToCVEs[t], label)
			}
		}
		if isWebVuln(v) && len(webCVEs) < 5 {
			webCVEs = appendUniqueStr(webCVEs, label)
		}
	}

	// Load existing exploit_targets keyed by normalized host:port
	existingTargets, _ := m.GetTargets()
	byHostPort := map[string]ExploitTarget{}
	for _, et := range existingTargets {
		key := fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSpace(et.Host)), et.Port)
		byHostPort[key] = et
	}

	// Query authorized assets registered in ARTEX's assets inventory
	rows, err := m.db.Query(`
		SELECT id, type, COALESCE(domain, ''), COALESCE(root_domain, ''), COALESCE(ip, ''),
		       port, COALESCE(url, ''), COALESCE(service_type, ''), COALESCE(service_name, ''),
		       COALESCE(page_title, ''), COALESCE(array_to_json(technologies)::text, '[]'), COALESCE(open_ports::text, '[]')
		FROM assets
		WHERE type IN ('service', 'subdomain', 'root_domain', 'ip')
		ORDER BY id DESC
		LIMIT 300`)
	if err != nil {
		return nil, nil // assets table may not exist in standalone unit tests
	}
	defer rows.Close()

	var matched []AutoMatchEntry
	seenHostPort := map[string]bool{}

	for rows.Next() {
		var (
			assetID                                                        int64
			aType, domain, rootDom, ipStr, rawURL, svcType, svcName, title string
			techJSON, portsJSON                                            string
			portNull                                                       sql.NullInt64
		)
		if err := rows.Scan(&assetID, &aType, &domain, &rootDom, &ipStr, &portNull, &rawURL, &svcType, &svcName, &title, &techJSON, &portsJSON); err != nil {
			continue
		}

		host, port, scheme := deriveAssetEndpoint(aType, domain, rootDom, ipStr, rawURL, svcType, portNull)
		if host == "" {
			continue
		}
		hpKey := fmt.Sprintf("%s:%d", strings.ToLower(host), port)
		if seenHostPort[hpKey] {
			continue
		}

		var techList []string
		_ = json.Unmarshal([]byte(techJSON), &techList)
		fingerprintBlob := strings.ToLower(strings.Join(techList, " ") + " " + svcType + " " + svcName + " " + title + " " + rawURL + " " + portsJSON)

		var hitTechs, hitCVEs []string
		for tech, cves := range techToCVEs {
			if containsWordOrToken(fingerprintBlob, tech) {
				hitTechs = appendUniqueStr(hitTechs, tech)
				for _, c := range cves {
					hitCVEs = appendUniqueStr(hitCVEs, c)
				}
			}
		}

		// If an authorized web asset has not been tech-fingerprinted yet and web CVEs are active,
		// enroll it for non-destructive tech-stack fingerprinting & verification within authorized scope.
		isWebEndpoint := scheme == "http" || scheme == "https" || port == 80 || port == 443 || port == 8080 || port == 8443
		if len(hitTechs) == 0 && isWebEndpoint && len(techList) == 0 && len(webCVEs) > 0 {
			hitTechs = []string{"web-fingerprint-pending"}
			hitCVEs = webCVEs
		}
		if len(hitTechs) == 0 {
			continue
		}
		seenHostPort[hpKey] = true

		svcLabel := strings.TrimSpace(svcName)
		if svcLabel == "" && len(techList) > 0 {
			svcLabel = strings.Join(techList, ", ")
		}
		if svcLabel == "" {
			svcLabel = scheme
		}
		note := fmt.Sprintf("Auto-targeted from authorized Asset #%d | Tech: %s | CVEs: %s",
			assetID, strings.Join(hitTechs, ", "), strings.Join(hitCVEs, ", "))

		if ex, exists := byHostPort[hpKey]; exists {
			_, _ = m.db.Exec(`UPDATE exploit_targets SET service = COALESCE(NULLIF($2,''), service), notes = $3 WHERE id = $1`, ex.ID, svcLabel, note)
			matched = append(matched, AutoMatchEntry{
				TargetID: ex.ID, Name: ex.Name, Host: ex.Host, Port: ex.Port,
				Service: svcLabel, MatchedTech: hitTechs, MatchedCVEs: hitCVEs, NewlyAdded: false,
			})
			continue
		}

		targetName := host
		if title != "" && len(title) <= 48 {
			targetName = fmt.Sprintf("%s (%s)", host, title)
		}
		targetType := "web"
		if !isWebEndpoint {
			targetType = "host"
		}
		newID, addErr := m.AddTarget(ExploitTarget{
			Name:        targetName,
			TargetType:  targetType,
			TargetValue: fmt.Sprintf("%s://%s:%d", scheme, host, port),
			Host:        host,
			Port:        port,
			Service:     svcLabel,
			Notes:       note,
			Status:      "matched",
		})
		if addErr == nil && newID > 0 {
			matched = append(matched, AutoMatchEntry{
				TargetID: newID, Name: targetName, Host: host, Port: port,
				Service: svcLabel, MatchedTech: hitTechs, MatchedCVEs: hitCVEs, NewlyAdded: true,
			})
		}
	}
	return matched, nil
}

// UpdateTargetVerification updates a target's status, detected service/version, and notes.
func (m *Monitor) UpdateTargetVerification(id int64, status, service, version, notes string) error {
	if m == nil || m.db == nil {
		return fmt.Errorf("monitor not initialized")
	}
	_, err := m.db.Exec(`
		UPDATE exploit_targets
		SET status = COALESCE(NULLIF($2, ''), status),
		    service = COALESCE(NULLIF($3, ''), service),
		    version = COALESCE(NULLIF($4, ''), version),
		    notes = CASE WHEN $5 <> '' THEN $5 ELSE notes END
		WHERE id = $1`,
		id, strings.TrimSpace(status), strings.TrimSpace(service), strings.TrimSpace(version), strings.TrimSpace(notes),
	)
	return err
}

func deriveAssetEndpoint(aType, domain, rootDom, ipStr, rawURL, svcType string, portNull sql.NullInt64) (host string, port int, scheme string) {
	scheme = "https"
	if rawURL != "" {
		if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
			if u.Scheme != "" {
				scheme = strings.ToLower(u.Scheme)
			}
			h, pStr, splitErr := net.SplitHostPort(u.Host)
			if splitErr == nil {
				host = h
				port, _ = strconv.Atoi(pStr)
			} else {
				host = u.Hostname()
			}
		}
	}
	if host == "" {
		switch {
		case domain != "":
			host = domain
		case rootDom != "":
			host = rootDom
		case ipStr != "":
			host = ipStr
			scheme = "http"
		}
	}
	if port <= 0 && portNull.Valid && portNull.Int64 > 0 {
		port = int(portNull.Int64)
	}
	if port <= 0 {
		if scheme == "http" {
			port = 80
		} else {
			port = 443
		}
	}
	if port == 80 && scheme == "https" && rawURL == "" {
		scheme = "http"
	}
	if strings.EqualFold(svcType, "ssh") {
		scheme = "ssh"
	}
	return strings.TrimSpace(host), port, scheme
}

func appendUniqueStr(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

var reSecurityContactLine = regexp.MustCompile(`(?im)^Contact:\s*(.+)$`)

var excludedDirectoryDomains = []string{
	"github.com", "githubusercontent.com", "gitlab.com", "stackoverflow.com", "stackexchange.com",
	"reddit.com", "youtube.com", "wikipedia.org", "medium.com", "npmjs.com", "pypi.org",
	"packagist.org", "docker.com", "nvd.nist.gov", "cve.org", "mitre.org", "cisa.gov",
	"exploit-db.com", "sploitus.com", "bleepingcomputer.com", "thehackernews.com", "portswigger.net",
	"news.ycombinator.com", "cloudflare.com", "microsoft.com", "apple.com", "google.com", "amazon.com",
}

// NotificationCandidateEntry describes a publicly indexed website running an affected
// technology, enrolled passively for responsible vulnerability notification (never auto-exploited).
type NotificationCandidateEntry struct {
	TargetID          int64  `json:"target_id"`
	Host              string `json:"host"`
	URL               string `json:"url"`
	DetectedTech      string `json:"detected_tech"`
	DisclosureContact string `json:"disclosure_contact"`
	NewlyAdded        bool   `json:"newly_added"`
	Notes             string `json:"notes"`
}

// EnrollNotificationCandidates passively inspects public candidate URLs discovered via
// search engines for a vulnerable technology/platform, looks up RFC 9116 /.well-known/security.txt
// disclosure contacts, and adds them to Patch Monitor's Targets table with status="notify_candidate"
// so operators can notify affected site owners responsibly (without running active exploits).
func (m *Monitor) EnrollNotificationCandidates(technology, cveOrIssue string, candidateURLs []string) ([]NotificationCandidateEntry, error) {
	if m == nil || m.db == nil {
		return nil, fmt.Errorf("monitor not initialized")
	}
	tech := strings.TrimSpace(technology)
	if tech == "" {
		return nil, fmt.Errorf("technology is required")
	}

	existingTargets, _ := m.GetTargets()
	byHost := map[string]ExploitTarget{}
	for _, et := range existingTargets {
		byHost[strings.ToLower(strings.TrimSpace(et.Host))] = et
	}

	client := m.client()
	var results []NotificationCandidateEntry
	seenHosts := map[string]bool{}

	for _, rawURL := range candidateURLs {
		if len(results) >= 12 {
			break
		}
		u, err := url.Parse(strings.TrimSpace(rawURL))
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if seenHosts[host] || isExcludedReferenceDomain(host) {
			continue
		}
		seenHosts[host] = true

		scheme := "https"
		if strings.EqualFold(u.Scheme, "http") {
			scheme = "http"
		}
		port := 443
		if scheme == "http" {
			port = 80
		}
		if p := u.Port(); p != "" {
			if pn, perr := strconv.Atoi(p); perr == nil && pn > 0 {
				port = pn
			}
		}
		origin := fmt.Sprintf("%s://%s", scheme, u.Host)

		// Passive read-only header & RFC 9116 security.txt lookup
		detectedHeader := tech
		if req, rerr := http.NewRequest(http.MethodGet, origin, nil); rerr == nil {
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARTEX-AdvisoryNotifier/2.2)")
			if resp, derr := client.Do(req); derr == nil {
				srv := strings.TrimSpace(resp.Header.Get("Server"))
				xpb := strings.TrimSpace(resp.Header.Get("X-Powered-By"))
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
				var parts []string
				if srv != "" {
					parts = append(parts, srv)
				}
				if xpb != "" {
					parts = append(parts, xpb)
				}
				if len(parts) > 0 {
					detectedHeader = fmt.Sprintf("%s (%s)", tech, strings.Join(parts, " / "))
				}
			}
		}

		contact := lookupSecurityTxtContact(client, origin, host)
		issueTag := strings.TrimSpace(cveOrIssue)
		if issueTag == "" {
			issueTag = "Technology Exposure"
		}
		note := fmt.Sprintf("Notification Candidate (%s) | Tech: %s | Contact: %s", issueTag, detectedHeader, contact)

		if ex, exists := byHost[host]; exists {
			results = append(results, NotificationCandidateEntry{
				TargetID: ex.ID, Host: host, URL: origin, DetectedTech: detectedHeader,
				DisclosureContact: contact, NewlyAdded: false, Notes: ex.Notes,
			})
			continue
		}

		newID, addErr := m.AddTarget(ExploitTarget{
			Name:        host,
			TargetType:  "web",
			TargetValue: origin,
			Host:        host,
			Port:        port,
			Service:     detectedHeader,
			Notes:       note,
			Status:      "notify_candidate",
		})
		if addErr == nil && newID > 0 {
			results = append(results, NotificationCandidateEntry{
				TargetID: newID, Host: host, URL: origin, DetectedTech: detectedHeader,
				DisclosureContact: contact, NewlyAdded: true, Notes: note,
			})
		}
	}
	return results, nil
}

func isExcludedReferenceDomain(host string) bool {
	for _, ex := range excludedDirectoryDomains {
		if host == ex || strings.HasSuffix(host, "."+ex) {
			return true
		}
	}
	return false
}

func lookupSecurityTxtContact(client *http.Client, origin, host string) string {
	for _, p := range []string{"/.well-known/security.txt", "/security.txt"} {
		req, err := http.NewRequest(http.MethodGet, origin+p, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARTEX-SecurityTxtLookup/2.2)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			matches := reSecurityContactLine.FindAllStringSubmatch(string(body), 3)
			if len(matches) > 0 {
				var contacts []string
				for _, m := range matches {
					contacts = append(contacts, strings.TrimSpace(m[1]))
				}
				return strings.Join(contacts, ", ")
			}
		}
	}
	return "security@" + host
}
