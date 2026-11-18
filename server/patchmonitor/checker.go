package patchmonitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

// checkSource fetches and processes a single source.
func (m *Monitor) checkSource(src PatchSource) {
	log.Printf("[patchmonitor] Checking: %s", src.Name)

	resp, err := m.httpClient.Get(src.URL)
	if err != nil {
		m.updateSourceStatus(src.ID, "error", fmt.Sprintf("fetch error: %v", err))
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		m.updateSourceStatus(src.ID, "error", fmt.Sprintf("read error: %v", err))
		return
	}

	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	if hashStr == src.LastHash {
		m.updateSourceStatus(src.ID, "success", "no changes")
		return
	}

	vulns := m.parseContent(src.SourceType, body)
	newCount := 0
	for _, v := range vulns {
		if err := m.storeVulnerability(src.ID, v); err == nil {
			newCount++
		}
	}

	m.updateSourceHash(src.ID, hashStr, "success", fmt.Sprintf("%d new", newCount))
	log.Printf("[patchmonitor] %s: %d new vulns", src.Name, newCount)
}

// parseContent dispatches to appropriate parser based on source type.
func (m *Monitor) parseContent(sourceType string, body []byte) []Vulnerability {
	switch sourceType {
	case "nvd":
		return parseNVD(body)
	case "github":
		return parseGitHub(body)
	case "exploitdb":
		return parseExploitDB(body)
	default:
		return parseGeneric(body)
	}
}
