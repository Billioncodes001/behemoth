package patchmonitor

import (
	"encoding/json"
	"log"
	"strings"
	"time"
)

// ---------- NVD Parser ----------

func parseNVD(body []byte) []Vulnerability {
	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID   string `json:"id"`
				Desc  []struct{ Value string `json:"value"` } `json:"descriptions"`
				Metrics struct {
					CVSS31 []struct {
						Data struct { Score *float64 `json:"score"` } `json:"cvssData"`
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
			CVEID: v.CVE.ID,
			Title: v.CVE.ID + ": " + truncate(desc, 100),
			Description: desc,
			Severity:     scoreToSeverity(score),
			Status:       "new",
			DiscoveredAt: time.Now(),
		})
	}
	return vulns
}

// ---------- GitHub Parser ----------

func parseGitHub(body []byte) []Vulnerability {
	var results []struct {
		GhsaID   string `json:"ghsa_id"`
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
	}

	if err := json.Unmarshal(body, &results); err != nil {
		if strings.Contains(string(body), "<html") {
			return []Vulnerability{{Title: "New Advisory", Severity: "medium", Status: "new", DiscoveredAt: time.Now()}}
		}
		return nil
	}

	var vulns []Vulnerability
	for _, r := range results {
		vulns = append(vulns, Vulnerability{
			CVEID: r.GhsaID, Title: r.Summary,
			Severity: strings.ToLower(r.Severity), Status: "new", DiscoveredAt: time.Now(),
		})
	}
	return vulns
}

// ---------- ExploitDB Parser ----------

func parseExploitDB(body []byte) []Vulnerability {
	var vulns []Vulnerability
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.Contains(line, "<title>") && !strings.Contains(line, "Exploit-DB") {
			if title := extractBetween(line, "<title>", "</title>"); title != "" {
				vulns = append(vulns, Vulnerability{
					Title: title, Severity: "high", Status: "new", DiscoveredAt: time.Now(),
				})
			}
		}
	}
	return vulns
}

// ---------- Generic JSON Parser ----------

func parseGeneric(body []byte) []Vulnerability {
	var data map[string]interface{}
	if json.Unmarshal(body, &data) != nil {
		return nil
	}

	var vulns []Vulnerability
	if items, ok := data["vulnerabilities"].([]interface{}); ok {
		for _, item := range items {
			if m, ok := item.(map[string]interface{}); ok {
				v := Vulnerability{Status: "new", DiscoveredAt: time.Now()}
				if id, ok := m["cve_id"].(string); ok { v.CVEID = id; v.Title = id }
				if t, ok := m["title"].(string); ok { v.Title = t }
				if d, ok := m["description"].(string); ok { v.Description = d }
				if s, ok := m["severity"].(string); ok { v.Severity = s }
				vulns = append(vulns, v)
			}
		}
	}
	return vulns
}

// ---------- Helpers ----------

func scoreToSeverity(s *float64) string {
	if s == nil { return "medium" }
	switch {
	case *s >= 9.0: return "critical"
	case *s >= 7.0: return "high"
	case *s >= 4.0: return "medium"
	default: return "low"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n] + "..."
}

func extractBetween(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 { return "" }
	i += len(start)
	if j := strings.Index(s[i:], end); j >= 0 { return s[i : i+j] }
	return s[i:]
}
