package patchmonitor

import (
	"encoding/json"
	"html"
	"log"
	"regexp"
	"strings"
	"time"
)

var (
	reCVEID       = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	reXMLItem     = regexp.MustCompile(`(?is)<(?:item|entry)\b[^>]*>(.*?)</(?:item|entry)>`)
	reXMLTitle    = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reXMLDesc     = regexp.MustCompile(`(?is)<(?:description|summary|content)[^>]*>(.*?)</(?:description|summary|content)>`)
	reXMLCDATAStr = regexp.MustCompile(`(?is)<!\[CDATA\[(.*?)\]\]>`)
	reHTMLTags    = regexp.MustCompile(`<[^>]+>`)
)

// ---------- NVD Parser ----------

func parseNVD(body []byte) []Vulnerability {
	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID   string `json:"id"`
				Desc []struct {
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSS31 []struct {
						Data struct {
							Score *float64 `json:"score"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[patchmonitor] NVD parse error: %v", err)
		return nil
	}

	var vulns []Vulnerability
	for _, v := range result.Vulnerabilities {
		desc := ""
		if len(v.CVE.Desc) > 0 {
			desc = v.CVE.Desc[0].Value
		}
		var score *float64
		if len(v.CVE.Metrics.CVSS31) > 0 {
			score = v.CVE.Metrics.CVSS31[0].Data.Score
		}

		vulns = append(vulns, Vulnerability{
			CVEID:        v.CVE.ID,
			Title:        v.CVE.ID + ": " + truncate(desc, 110),
			Description:  desc,
			Severity:     scoreToSeverity(score),
			CVSSScore:    score,
			Status:       "active",
			DiscoveredAt: time.Now(),
		})
	}
	return vulns
}

// ---------- CISA KEV Parser ----------

func parseCISAKEV(body []byte) []Vulnerability {
	var result struct {
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			ShortDescription  string `json:"shortDescription"`
			RequiredAction    string `json:"requiredAction"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	items := result.Vulnerabilities
	if len(items) > 15 {
		items = items[:15]
	}
	var vulns []Vulnerability
	for _, it := range items {
		score := 8.8
		vulns = append(vulns, Vulnerability{
			CVEID:            it.CVEID,
			Title:            "[" + it.VendorProject + " " + it.Product + "] " + it.VulnerabilityName,
			Description:      it.ShortDescription,
			Severity:         "high",
			CVSSScore:        &score,
			AffectedVersions: it.VendorProject + " " + it.Product,
			PatchedVersion:   it.RequiredAction,
			Status:           "exploitable",
			DiscoveredAt:     time.Now(),
		})
	}
	return vulns
}

// ---------- Microsoft MSRC Parser ----------

func parseMSRC(body []byte) []Vulnerability {
	var result struct {
		Value []struct {
			ID            string `json:"ID"`
			DocumentTitle string `json:"DocumentTitle"`
			CvrfUrl       string `json:"CvrfUrl"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return parseRSSOrHTML(body, "Microsoft Windows")
	}
	items := result.Value
	if len(items) > 10 {
		items = items[len(items)-10:]
	}
	var vulns []Vulnerability
	for _, it := range items {
		score := 8.5
		vulns = append(vulns, Vulnerability{
			CVEID:            "MSRC-" + it.ID,
			Title:            "Microsoft Windows Security Update: " + it.DocumentTitle,
			Description:      "Official Microsoft Security Response Center (MSRC) release " + it.ID + " (" + it.DocumentTitle + ")",
			Severity:         "high",
			CVSSScore:        &score,
			AffectedVersions: "Windows 10 / Windows 11 / Windows Server",
			PatchedVersion:   it.ID,
			PatchURL:         it.CvrfUrl,
			Status:           "active",
			DiscoveredAt:     time.Now(),
		})
	}
	return vulns
}

// ---------- Red Hat Security Data Parser ----------

func parseRedHat(body []byte) []Vulnerability {
	var items []struct {
		CVE              string   `json:"CVE"`
		Severity         string   `json:"severity"`
		BugzillaDesc     string   `json:"bugzilla_description"`
		AffectedPackages []string `json:"affected_packages"`
		ResourceURL      string   `json:"resource_url"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return parseRSSOrHTML(body, "Red Hat")
	}
	if len(items) > 15 {
		items = items[:15]
	}
	var vulns []Vulnerability
	for _, it := range items {
		sev := strings.ToLower(it.Severity)
		switch sev {
		case "important":
			sev = "high"
		case "moderate":
			sev = "medium"
		case "critical", "high", "medium", "low":
		default:
			sev = "medium"
		}
		vulns = append(vulns, Vulnerability{
			CVEID:            it.CVE,
			Title:            truncate(it.BugzillaDesc, 120),
			Description:      it.BugzillaDesc,
			Severity:         sev,
			AffectedVersions: truncate(strings.Join(it.AffectedPackages, ", "), 200),
			PatchURL:         it.ResourceURL,
			Status:           "active",
			DiscoveredAt:     time.Now(),
		})
	}
	return vulns
}

// ---------- GitHub Advisory Parser ----------

func parseGitHub(body []byte) []Vulnerability {
	var results []struct {
		GhsaID      string `json:"ghsa_id"`
		CveID       string `json:"cve_id"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		HTMLURL     string `json:"html_url"`
	}

	if err := json.Unmarshal(body, &results); err != nil {
		return parseRSSOrHTML(body, "GitHub")
	}

	var vulns []Vulnerability
	for _, r := range results {
		id := r.CveID
		if id == "" {
			id = r.GhsaID
		}
		sev := strings.ToLower(r.Severity)
		if sev == "" {
			sev = "medium"
		}
		vulns = append(vulns, Vulnerability{
			CVEID:        id,
			Title:        r.Summary,
			Description:  truncate(r.Description, 600),
			Severity:     sev,
			PatchURL:     r.HTMLURL,
			Status:       "active",
			DiscoveredAt: time.Now(),
		})
	}
	return vulns
}

// ---------- ExploitDB & RSS / Atom / Apple HTML Parser ----------

func parseExploitDB(body []byte) []Vulnerability {
	return parseRSSOrHTML(body, "Exploit-DB")
}

func parseRSSOrHTML(body []byte, vendorHint string) []Vulnerability {
	text := string(body)
	var vulns []Vulnerability

	matches := reXMLItem.FindAllStringSubmatch(text, 15)
	for _, m := range matches {
		itemXML := m[1]
		title := cleanXMLText(firstSubmatch(reXMLTitle, itemXML))
		desc := cleanXMLText(firstSubmatch(reXMLDesc, itemXML))
		if title == "" {
			continue
		}
		cve := reCVEID.FindString(title + " " + desc)
		sev := inferSeverityFromText(title + " " + desc)
		vulns = append(vulns, Vulnerability{
			CVEID:            cve,
			Title:            truncate(title, 140),
			Description:      truncate(desc, 500),
			Severity:         sev,
			AffectedVersions: vendorHint,
			Status:           "active",
			DiscoveredAt:     time.Now(),
		})
	}
	if len(vulns) > 0 {
		return vulns
	}

	cves := reCVEID.FindAllString(text, 10)
	seen := map[string]bool{}
	for _, cve := range cves {
		if seen[cve] {
			continue
		}
		seen[cve] = true
		vulns = append(vulns, Vulnerability{
			CVEID:            cve,
			Title:            vendorHint + " Security Patch Advisory (" + cve + ")",
			Description:      "Discovered in " + vendorHint + " security release advisory feed.",
			Severity:         "high",
			AffectedVersions: vendorHint,
			Status:           "active",
			DiscoveredAt:     time.Now(),
		})
	}
	return vulns
}

// ---------- Generic JSON Parser ----------

func parseGeneric(body []byte) []Vulnerability {
	var data map[string]interface{}
	if json.Unmarshal(body, &data) != nil {
		return parseRSSOrHTML(body, "Vendor Advisory")
	}

	var vulns []Vulnerability
	if items, ok := data["vulnerabilities"].([]interface{}); ok {
		for _, item := range items {
			if m, ok := item.(map[string]interface{}); ok {
				v := Vulnerability{Status: "active", DiscoveredAt: time.Now()}
				if id, ok := m["cve_id"].(string); ok {
					v.CVEID = id
					v.Title = id
				}
				if t, ok := m["title"].(string); ok {
					v.Title = t
				}
				if d, ok := m["description"].(string); ok {
					v.Description = d
				}
				if s, ok := m["severity"].(string); ok {
					v.Severity = s
				}
				vulns = append(vulns, v)
			}
		}
	}
	return vulns
}

// ---------- Helpers ----------

func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func cleanXMLText(s string) string {
	if m := reXMLCDATAStr.FindStringSubmatch(s); len(m) > 1 {
		s = m[1]
	}
	s = html.UnescapeString(s)
	s = reHTMLTags.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(s), " ")
}

func inferSeverityFromText(s string) string {
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "critical") || strings.Contains(low, "zero-day") || strings.Contains(low, "0-day") || strings.Contains(low, "unauthenticated rce") || strings.Contains(low, "remote code execution"):
		return "critical"
	case strings.Contains(low, "high") || strings.Contains(low, "privilege escalation") || strings.Contains(low, "command injection") || strings.Contains(low, "authentication bypass") || strings.Contains(low, "sql injection"):
		return "high"
	case strings.Contains(low, "low"):
		return "low"
	default:
		return "medium"
	}
}

func scoreToSeverity(s *float64) string {
	if s == nil {
		return "medium"
	}
	switch {
	case *s >= 9.0:
		return "critical"
	case *s >= 7.0:
		return "high"
	case *s >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
