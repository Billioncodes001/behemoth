package patchmonitor

import (
	"strings"
	"testing"
)

func TestNucleiTemplateYAML_BasicShape(t *testing.T) {
	e := nucleiTemplateEntry{
		ID:          7,
		CVEID:       "CVE-2024-1234",
		Title:       "Test \"Title\" with quotes",
		Severity:    "high",
		ExploitCode: "import requests\nurl = \"http://target/vuln?id=1\"\nr = requests.get(url)\nif r.status_code == 200:\n    print(\"[+] vuln\")\n",
		Status:      "verified_working",
	}
	out := nucleiTemplateYAML(e)

	for _, want := range []string{
		"id: artex-cve-2024-1234",
		"severity: high",
		"tags: artex,patch-monitor",
		"cve-id: CVE-2024-1234",
		"\"{{BaseURL}}/vuln?id=1\"",
		"method: GET",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("template output missing %q\n---\n%s", want, out)
		}
	}
	// Title quotes must be escaped inside YAML double quotes.
	if !strings.Contains(out, "Test \\\"Title\\\" with quotes") {
		t.Errorf("title not escaped correctly:\n%s", out)
	}
	// Nuclei placeholder must not be escaped.
	if strings.Contains(out, "\\{\\{BaseURL\\}\\}") {
		t.Errorf("BaseURL placeholder must stay raw:\n%s", out)
	}
}

func TestNucleiTemplateYAML_UnknownSeverityDefaultsToMedium(t *testing.T) {
	e := nucleiTemplateEntry{ID: 3, Title: "x", Severity: "banana"}
	if out := nucleiTemplateYAML(e); !strings.Contains(out, "severity: medium") {
		t.Errorf("expected severity fallback to medium:\n%s", out)
	}
}

func TestTemplateSlug(t *testing.T) {
	if got := templateSlug(nucleiTemplateEntry{ID: 9, CVEID: "CVE 2024/ 99"}); got != "cve-2024-99" {
		t.Errorf("templateSlug = %q, want cve-2024-99", got)
	}
	if got := templateSlug(nucleiTemplateEntry{ID: 9}); got != "exploit-9" {
		t.Errorf("templateSlug (no cve) = %q, want exploit-9", got)
	}
}

func TestExtractHTTPRequest(t *testing.T) {
	m, p := extractHTTPRequest("payload\nGET /admin/backup.zip HTTP/1.1\nHost: x")
	if m != "GET" || p != "/admin/backup.zip" {
		t.Errorf("extractHTTPRequest raw = %q %q", m, p)
	}
	m, p = extractHTTPRequest("requests.get('https://h.example.com/a/b?c=1')")
	if m != "GET" || p != "/a/b?c=1" {
		t.Errorf("extractHTTPRequest url = %q %q", m, p)
	}
	m, _ = extractHTTPRequest("no url here")
	if m != "" {
		t.Errorf("expected empty method, got %q", m)
	}
}

func TestExtractFingerprintWords(t *testing.T) {
	words := extractFingerprintWords(`print("[+] Potential RCE")\nassert 'admin_backup' in body`)
	found := false
	for _, w := range words {
		if w == "admin_backup" {
			found = true
		}
	}
	if !found {
		t.Errorf("fingerprint words missing admin_backup: %v", words)
	}
	for _, w := range words {
		if strings.HasPrefix(w, "http") {
			t.Errorf("URL leaked into fingerprint words: %v", words)
		}
	}
}
