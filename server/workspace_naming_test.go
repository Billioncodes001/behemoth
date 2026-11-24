package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/behemoth/db"
)

func TestBaseDomainOf(t *testing.T) {
	cases := map[string]string{
		"portal.uniosun.edu.ng":                "uniosun.edu.ng",
		"api-prod.inecnigeria.org":             "inecnigeria.org",
		"inecnigeria.org":                      "inecnigeria.org",
		"a.b.c.example.co.uk":                  "example.co.uk",
		"shop.example.com":                     "example.com",
		"107.180.188.171":                      "107.180.188.171",
		"localhost":                            "localhost",
		"UPPER.Case.Example.COM":               "example.com",
		"deep.sub.inecnigeria.org.":            "inecnigeria.org",
		"api.croms.inecnigeria.org":            "inecnigeria.org",
		"phpm5.uniosun.edu.ng":                 "uniosun.edu.ng",
		"api.postgraduate.uniosun.edu.ng":      "uniosun.edu.ng",
		"dolphin-app-sleqh.ondigitalocean.app": "ondigitalocean.app",
	}
	for in, want := range cases {
		if got := baseDomainOf(in); got != want {
			t.Errorf("baseDomainOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// Sessions must be labelled by the base domain they worked on even when the
// conversation title carries no URL — the domain-scoped workspace link inside
// the session dir is the fallback signal.
func TestWorkspaceSessionDisplayUsesSessionDomainLink(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)

	conv, err := s.m.pg.CreateConversation("auto", "So, I want you to carry out a full vulne...", nil)
	if err != nil {
		t.Fatal(err)
	}
	sessID := s.convBusyKey(conv.ID)
	s.ensureDomainWorkspaceStructure("panel.uniosun.edu.ng", sessID)

	// Title and first message carry no domain — only the session link does.
	if err := os.MkdirAll(filepath.Join(s.m.dir, "sessions", sessID), 0o755); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.wsList(w, httptest.NewRequest(http.MethodGet, "/api/workspace/list?path=sessions", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "uniosun.edu.ng ("+sessID+")") {
		t.Fatalf("expected base-domain label from session link, got %s", body)
	}
	if strings.Contains(body, "So, I want you to carry out") {
		t.Fatalf("expected the conversation title to be replaced by the domain label, got %s", body)
	}
}

// The first user message is the last-resort domain source when neither the
// title nor the session contents carry one.
func TestWorkspaceSessionDisplayUsesFirstMessage(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)

	conv, err := s.m.pg.CreateConversation("auto", "full vulnerability assessment", nil)
	if err != nil {
		t.Fatal(err)
	}
	sessID := s.convBusyKey(conv.ID)
	if err := os.MkdirAll(filepath.Join(s.m.dir, "sessions", sessID), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.AppendConvActivity(conv.ID, db.Activity{Kind: "user", Detail: "Scan https://portal.uniosun.edu.ng/login"}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.wsList(w, httptest.NewRequest(http.MethodGet, "/api/workspace/list?path=sessions", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "uniosun.edu.ng ("+sessID+")") {
		t.Fatalf("expected base-domain label from first message, got %s", w.Body.String())
	}
}
